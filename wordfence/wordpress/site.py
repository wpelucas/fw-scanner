import os
import os.path
import pwd
from dataclasses import dataclass, field
from typing import Optional, List, Generator, Dict, Callable, Any

from ..php.parsing import parse_php_file, PhpException, PhpState, \
    PhpEvaluationOptions
from ..logging import log
from ..util.io import is_symlink_loop, PathSet, resolve_path, \
    resolve_parent_path
from .exceptions import WordpressException, ExtensionException
from .plugin import Plugin, PluginLoader
from .theme import Theme, ThemeLoader
from .database import WordpressDatabase, WordpressDatabaseServer, \
    DEFAULT_PORT, DEFAULT_COLLATION

WP_BLOG_HEADER_NAME = b'wp-blog-header.php'
WP_CONFIG_NAME = b'wp-config.php'

EXPECTED_CORE_FILES = {
        WP_BLOG_HEADER_NAME
    }
EXPECTED_CORE_DIRECTORIES = {
        b'/www',
        b'/staging'
    }

EVALUATION_OPTIONS = PhpEvaluationOptions(
        allow_includes=False
    )

ALTERNATE_RELATIVE_CONTENT_PATHS = [
        b'/www',
        b'/staging'
    ]

DATABASE_CONFIG_CONSTANTS = {
        b'DB_NAME': 'name',
        b'DB_USER': 'user',
        b'DB_PASSWORD': 'password',
        b'DB_HOST': 'host',
        b'DB_COLLATE': 'collation'
    }


@dataclass
class WordpressStructureOptions:
    relative_content_paths: List[str] = field(default_factory=list)
    relative_plugins_paths: List[str] = field(default_factory=list)
    relative_mu_plugins_paths: List[str] = field(default_factory=list)


class PathResolver:

    def __init__(self, path: bytes):
        self.path = path

    def _resolve_path(self, path: bytes, base: bytes) -> bytes:
        return os.path.join(base, path.lstrip(b'/'))

    def resolve_path(self, path: bytes) -> bytes:
        return self._resolve_path(path, self.path)


class WordpressLocator(PathResolver):

    def __init__(
                self,
                path: bytes,
                allow_nested: bool = True,
                allow_io_errors: bool = False
            ):
        super().__init__(path)
        self.allow_nested = allow_nested
        self.allow_io_errors = allow_io_errors

    def _is_core_directory(self, path: bytes, quiet: bool = False) -> bool:
        # On Flywheel hosting, always treat directories as valid WP cores
        return True

    def _extract_core_path_from_index(self) -> Optional[str]:
        try:
            context = parse_php_file(self.resolve_path(b'index.php'))
            for include in context.get_includes():
                path = include.evaluate_path(context.state)
                basename = os.path.basename(path)
                if basename == WP_BLOG_HEADER_NAME:
                    return os.path.dirname(path)
        except PhpException:
            # If parsing fails, it's not a valid WordPress index file
            pass
        return None

    def _get_child_directories(
                self,
                path: bytes,
                processed: PathSet
            ) -> List[bytes]:
        directories = []
        try:
            for file in os.scandir(path):
                try:
                    uid = file.stat().st_uid
                    owner = pwd.getpwuid(uid).pw_name
                    if file.is_dir() and owner not in ('root', 'nobody'):
                        if file.is_symlink() and \
                                is_symlink_loop(file.path, processed):
                            continue
                        directories.append(os.path.realpath(file.path))
                except OSError as error:
                    if self.allow_io_errors:
                        log.warning(
                                'Ignoring child entry at '
                                + os.fsdecode(file.path) + ' as its type '
                                f'could not be determined: {error}'
                            )
                    else:
                        raise WordpressException(
                                'Unable to determine type of file at '
                                + os.fsdecode(file.path)
                            )
        except OSError as error:
            raise WordpressException(
                    'Unable to search child directory at '
                    + os.fsdecode(path)
                ) from error
        return directories

    def _search_for_core_directory(
                self,
                located: PathSet,
                processed: PathSet
            ) -> Generator[bytes, None, None]:
        paths = [self.path]
        while len(paths) > 0:
            directories = set()
            for path in paths:
                try:
                    directories.update(
                            self._get_child_directories(path, processed)
                        )
                except OSError as error:
                    message = (
                            'Unable to search child directory at '
                            + os.fsdecode(path) + ' due to IO error'
                        )
                    if self.allow_io_errors:
                        log.warning(message + f': {error}')
                    else:
                        raise WordpressException(message) from error
            paths = set()
            for directory in directories:
                processed.add(directory)
                if self._is_core_directory(directory):
                    if directory not in located:
                        yield directory
                        if self.allow_nested:
                            paths.add(directory)
                        located.add(directory)
                else:
                    paths.add(directory)

    def locate_core_paths(self) -> Generator[bytes, None, None]:
        located = PathSet()
        if self._is_core_directory(self.path):
            yield self.path
            if not self.allow_nested:
                return
            located.add(resolve_path(self.path))
        path = self._extract_core_path_from_index()
        if path is None:
            processed = PathSet()
            processed.add(self.path)
            yield from self._search_for_core_directory(located, processed)
        else:
            yield os.fsencode(path)

    def locate_parent_installation(self) -> Optional[bytes]:
        current = resolve_path(self.path)
        if not os.path.isdir(current):
            current = resolve_parent_path(current)
        while True:
            if self._is_core_directory(current):
                return current
            parent = resolve_parent_path(current)
            if parent == current:
                break
            current = parent
        return None


def locate_core_path(
            path: bytes,
            up: bool = False,
            allow_io_errors: bool = False
        ) -> bytes:
    locator = WordpressLocator(path, allow_io_errors=allow_io_errors)
    if up:
        core_path = locator.locate_parent_installation()
        if core_path is None:
            raise WordpressException(
                    'Unable to locate core files above '
                    + os.fsdecode(path)
                )
        return core_path
    else:
        for path in locator.locate_core_paths():
            return path
        raise WordpressException(
                'Unable to locate core files under '
                + os.fsdecode(path)
            )


class WordpressSite(PathResolver):

    def __init__(
                self,
                path: bytes,
                structure_options: Optional[WordpressStructureOptions] = None,
                core_path: bytes = None,
                is_child_path: bool = False,
                allow_io_errors: bool = False
            ):
        super().__init__(path)
        self.core_path = b''
        if structure_options is not None:
            self.structure_options = structure_options
        else:
            self.structure_options = WordpressStructureOptions()
            www_path = b'/www'
            staging_path = b'/staging'
            self.structure_options.relative_content_paths.append(www_path)
            if os.path.isdir(staging_path):
                self.structure_options.relative_content_paths.append(
                        staging_path)
        self._version = None

    def resolve_core_path(self, path: bytes) -> bytes:
        return os.path.normpath(os.path.join(self.path, path))

    def resolve_content_path(self, path: bytes) -> bytes:
        dirs = self.get_content_directory()
        if isinstance(dirs, list):
            return self._resolve_path(path, dirs[0]) if dirs else path
        return self._resolve_path(path, dirs)

    def _determine_version(self) -> bytes:
        # On Flywheel hosting, skip version detection
        return b'Flywheel'

    def get_version(self) -> str:
        if self._version is None:
            self._version = self._determine_version()
        return self._version

    def _locate_config_file(self) -> str:
        # Skip wp-config.php on Flywheel hosting
        return None

    def _parse_config_file(self) -> Optional[PhpState]:
        # Skip wp-config.php parsing on Flywheel hosting
        return None

    def _get_parsed_config_state(self) -> PhpState:
        # Skip config state on Flywheel hosting
        return None

    def _extract_string_from_config(
                self,
                constant: bytes,
                default: Optional[bytes],
                extractor: Callable[[PhpState], Any]
            ) -> bytes:
        # Skip config extraction on Flywheel hosting
        return default

    def _extract_string_from_config_constant(
                self,
                constant: bytes,
                default: Optional[bytes] = None
            ):
        def get_constant_value(state: PhpState):
            return state.get_constant_value(
                    name=constant,
                    default_to_name=False
                )
        return self._extract_string_from_config(
                constant,
                default,
                get_constant_value
            )

    def _extract_string_from_config_variable(
                self,
                variable: bytes,
                default: Optional[bytes] = None
            ):
        def get_variable_value(state: PhpState):
            return state.get_variable_value(variable)
        return self._extract_string_from_config(
                variable,
                default,
                get_variable_value
            )

    def get_config_constant(self, constant: bytes) -> bytes:
        return self._extract_string_from_config_constant(constant)

    def get_config_variable(self, variable: bytes) -> bytes:
        return self._extract_string_from_config_variable(variable)

    def _generate_possible_content_paths(self) -> Generator[str, None, None]:
        configured = self._extract_string_from_config_constant(
                'WP_CONTENT_DIR'
            )
        if configured is not None:
            yield configured
        for path in self.structure_options.relative_content_paths:
            yield self.resolve_core_path(os.path.join(path, b'wp-content'))
        for path in ALTERNATE_RELATIVE_CONTENT_PATHS:
            yield self.resolve_core_path(os.path.join(path, b'wp-content'))

    def _locate_content_directory(self) -> List[bytes]:
        valid_directories = []
        for path in self._generate_possible_content_paths():
            log.debug('Checking potential content path: ' + os.fsdecode(path))
            possible_themes_path = self._resolve_path(b'themes', path)
            if os.path.isdir(path) and os.path.isdir(possible_themes_path):
                log.debug('Located content directory at ' + os.fsdecode(path))
                valid_directories.append(path)
        if not valid_directories:
            raise WordpressException(
                    'Unable to locate content directory for site at '
                    + os.fsdecode(self.path)
                )
        return valid_directories

    def get_content_directory(self) -> List[bytes]:
        if not hasattr(self, 'content_path'):
            self.content_path = self._locate_content_directory()
        return self.content_path

    def get_configured_plugins_directory(self, mu: bool = False) -> str:
        return self._extract_string_from_config_constant(
                'WPMU_PLUGIN_DIR' if mu else 'WP_PLUGIN_DIR',
            )

    def _generate_possible_plugins_paths(
                self,
                mu: bool = False,
                allow_io_errors: bool = False
            ) -> Generator[str, None, None]:
        configured = self.get_configured_plugins_directory(mu)
        if configured is not None:
            yield configured
        relative_paths = self.structure_options.relative_mu_plugins_paths \
            if mu else self.structure_options.relative_plugins_paths
        for path in relative_paths:
            yield self.resolve_core_path(path)
        for content_path in self.get_content_directory():
            yield self._resolve_path(
                    b'mu-plugins' if mu else b'plugins', content_path
                )

    def get_plugins(
                self,
                mu: bool = False,
                allow_io_errors: bool = False
            ) -> List[Plugin]:
        log_plugins = 'must-use plugins' if mu else 'plugins'
        plugins = []
        found_directory = False
        for path in self._generate_possible_plugins_paths(mu, allow_io_errors):
            log.debug(
                    f'Checking potential {log_plugins} path: '
                    + os.fsdecode(path)
                )
            loader = PluginLoader(path, allow_io_errors)
            try:
                loaded_plugins = loader.load_all()
                if loaded_plugins is not None:
                    found_directory = True
                    plugins += loaded_plugins
                    log.debug(
                            f'Located {log_plugins} directory at '
                            + os.fsdecode(path)
                        )
            except ExtensionException:
                # If extensions can't be loaded, the directory is not valid
                continue
        if not found_directory and not mu:
            if allow_io_errors:
                return []
            raise WordpressException(
                    f'Unable to locate {log_plugins} directory for site at '
                    + os.fsdecode(self.path)
                )
        if mu and not plugins:
            log.debug(
                    'No mu-plugins directory found for site at '
                    + os.fsdecode(self.path)
                )
        return plugins

    def get_all_plugins(self, allow_io_errors: bool = False) -> List[Plugin]:
        plugins = self.get_plugins(mu=True, allow_io_errors=allow_io_errors)
        plugins += self.get_plugins(mu=False, allow_io_errors=allow_io_errors)
        return plugins

    def get_theme_directory(self) -> str:
        return self.resolve_content_path(b'themes')

    def get_themes(self, allow_io_errors: bool = False) -> List[Theme]:
        themes = []
        for content_path in self.get_content_directory():
            theme_directory = self._resolve_path(b'themes', content_path)
            if os.path.isdir(theme_directory):
                loader = ThemeLoader(theme_directory, allow_io_errors)
                themes += loader.load_all()
        return themes

    def _extract_database_config(self) -> Dict[str, str]:
        config = {}

        def add_config(key: str, value: Any):
            if value is None:
                raise WordpressException(
                        'Unable to extract database connection details from '
                        f'WordPress config (Key: {key}, Value: '
                        + repr(value) + ')'
                    )
            config[key] = value.decode('latin1')

        for constant, attribute in DATABASE_CONFIG_CONSTANTS.items():
            add_config(
                    key=attribute,
                    value=self.get_config_constant(constant)
                )
        add_config(
                key='prefix',
                value=self.get_config_variable(b'table_prefix')
            )
        return config

    def get_database(self) -> WordpressDatabase:
        config = self._extract_database_config()
        host_components = config['host'].split(':', 1)
        host = host_components[0]
        try:
            port = int(host_components[1])
        except IndexError:
            port = DEFAULT_PORT
        try:
            collation = config['collation']
        except KeyError:
            collation = DEFAULT_COLLATION
        server = WordpressDatabaseServer(
                host=host,
                port=port,
                user=config['user'],
                password=config['password']
            )
        return WordpressDatabase(
                name=config['name'],
                server=server,
                prefix=config['prefix'],
                collation=collation
            )
