import os

from typing import List, Dict, Callable, Any, Optional
from email.message import EmailMessage
from email.headerregistry import Address

from ...intel.vulnerabilities import ScannableSoftware, Vulnerability, \
        Software, ProductionVulnerability
from ...api.intelligence import VulnerabilityFeedVariant
from ...util.terminal import Color, escape, RESET
from ...util.html import Tag
from ...util.versioning import version_to_str
from ..reporting import Report, ReportColumnEnum, ReportFormatEnum, \
        ReportRecord, ReportManager, ReportFormat, ReportColumn, \
        BaseHumanReadableWriter, ReportEmail, get_config_options, \
        generate_report_email_html, generate_html_table, \
        REPORT_FORMAT_CSV, REPORT_FORMAT_TSV, REPORT_FORMAT_NULL_DELIMITED, \
        REPORT_FORMAT_LINE_DELIMITED
from ..context import CliContext
from ..email import Mailer


class VulnScanReportColumn(ReportColumnEnum):
    SOFTWARE_TYPE = 'software_type', lambda record: record.software.type.value
    SLUG = 'slug', lambda record: record.software.slug
    VERSION = 'version', lambda record: version_to_str(record.software.version)
    ID = 'id', \
        lambda record: record.vulnerability.identifier
    TITLE = 'title', lambda record: record.vulnerability.title
    LINK = 'link', lambda record: record.vulnerability.get_wordfence_link()
    DESCRIPTION = 'description', \
        lambda record: record.vulnerability.description, \
        VulnerabilityFeedVariant.PRODUCTION
    CVE = 'cve', lambda record: record.vulnerability.cve, \
        VulnerabilityFeedVariant.PRODUCTION
    CVSS_VECTOR = 'cvss_vector', \
        lambda record: record.vulnerability.cvss.vector, \
        VulnerabilityFeedVariant.PRODUCTION
    CVSS_SCORE = 'cvss_score', \
        lambda record: record.vulnerability.cvss.score, \
        VulnerabilityFeedVariant.PRODUCTION
    CVSS_RATING = 'cvss_rating', \
        lambda record: record.vulnerability.cvss.rating, \
        VulnerabilityFeedVariant.PRODUCTION
    CWE_ID = 'cwe_id', \
        lambda record: record.vulnerability.cwe.identifier, \
        VulnerabilityFeedVariant.PRODUCTION
    CWE_NAME = 'cwe_name', \
        lambda record: record.vulnerability.cwe.name, \
        VulnerabilityFeedVariant.PRODUCTION
    CWE_DESCRIPTION = 'cwe_description', \
        lambda record: record.vulnerability.cwe.description, \
        VulnerabilityFeedVariant.PRODUCTION
    PATCHED = 'patched', \
        lambda record: record.get_matched_software().patched
    REMEDIATION = 'remediation', \
        lambda record: record.get_matched_software().remediation, \
        VulnerabilityFeedVariant.PRODUCTION,
    PUBLISHED = 'published', lambda record: record.vulnerability.published
    UPDATED = 'updated', \
        lambda record: record.vulnerability.updated, \
        VulnerabilityFeedVariant.PRODUCTION
    SCANNED_PATH = 'scanned_path', lambda record: os.fsdecode(
            record.software.scan_path
        )

    def __init__(
                self,
                header: str,
                extractor: Callable[[Any], str],
                feed_variant: Optional[VulnerabilityFeedVariant] = None
            ):
        super().__init__(header, extractor)
        self.feed_variant = feed_variant

    def is_compatible(
                self,
                variant: VulnerabilityFeedVariant
            ) -> bool:
        return self.feed_variant is None or \
                variant == self.feed_variant


class HumanReadableWriter(BaseHumanReadableWriter):

    def get_severity_color(self, severity: str) -> str:
        if severity == 'none' or severity == 'low':
            return escape(color=Color.BLUE, bold=True)
        if severity == 'high' or severity == 'critical':
            return escape(color=Color.RED, bold=True)
        return '\033[1;38;5;208m'

    def format_record(self, record) -> str:
        vuln = record.vulnerability
        sw = record.software
        yellow_bold = escape(color=Color.YELLOW, bold=True)
        link = vuln.get_wordfence_link()
        white = '\033[0;38;5;7m'
        symbol_color = '\033[0;38;5;7m'
        severity = None
        if isinstance(record.vulnerability, ProductionVulnerability):
            if record.vulnerability.cvss is not None:
                severity = record.vulnerability.cvss.rating
        if severity is None:
            severity_message = ''
        else:
            severity = severity.lower()
            severity_color = self.get_severity_color(severity)
            severity_message = f'{severity_color}{severity}{white} severity '

        # Split the vuln.title on the first occurrence of <=
        title_parts = vuln.title.split('<=', 1)
        title_start = title_parts[0].strip()
        title_end = title_parts[1].strip() if len(title_parts) > 1 else ""

        return (
            f'{yellow_bold}{title_start}{RESET} {symbol_color}<= '
            f'{white}{title_end}{RESET}\n'
            f'{white}Type: {sw.type}\n'
            f'{white}Slug: {sw.slug}\n'
            f'{white}Class: {severity_message}vulnerability\n'
            f'{white}Details: {link}{RESET}\n'
            )


REPORT_FORMAT_HUMAN = ReportFormat(
        'human',
        lambda stream, columns: HumanReadableWriter(stream),
        allows_headers=False,
        allows_column_customization=False
    )


class VulnScanReportFormat(ReportFormatEnum):
    CSV = REPORT_FORMAT_CSV
    TSV = REPORT_FORMAT_TSV
    NULL_DELIMITED = REPORT_FORMAT_NULL_DELIMITED
    LINE_DELIMITED = REPORT_FORMAT_LINE_DELIMITED
    HUMAN = REPORT_FORMAT_HUMAN


class VulnScanReportRecord(ReportRecord):

    def __init__(
                self,
                software: ScannableSoftware,
                vulnerability: Vulnerability
            ):
        self.software = software
        self.vulnerability = vulnerability
        self.matched_software = None

    def get_matched_software(self) -> Software:
        if self.matched_software is None:
            self.matched_software = \
                    self.vulnerability.get_matched_software(self.software)
        return self.matched_software


class VulnScanReport(Report):
    message_printed = False

    def __init__(
                self,
                format: VulnScanReportFormat,
                columns: List[VulnScanReportColumn],
                email_addresses: List[str],
                mailer: Optional[Mailer],
                write_headers: bool = False
            ):
        super().__init__(
                format=format,
                columns=columns,
                email_addresses=email_addresses,
                mailer=mailer,
                write_headers=write_headers
            )
        self.scanner = None

    def add_result(
                self,
                software: ScannableSoftware,
                vulnerabilities: Dict[str, Vulnerability]
            ) -> None:
        records = []
        for vulnerability in vulnerabilities.values():
            if vulnerability and not VulnScanReport.message_printed:
                print("\033[1m\033[36mPossible vulns found:\033[0m\n")
                VulnScanReport.message_printed = True
            record = VulnScanReportRecord(
                    software,
                    vulnerability
                )
            records.append(record)
        self.write_records(records)

    def __del__(self):
        if not VulnScanReport.message_printed:
            print("\033[1m\033[32mNo vulns found!\033[0m\n")

    def generate_email(
                self,
                recipient: Address,
                attachments: Dict[str, str],
                hostname: str
            ) -> EmailMessage:

        unique_count = self.scanner.get_vulnerability_count()
        total_count = self.scanner.get_total_count()

        base_message = 'Vulnerabilities were found by Wordfence CLI during ' \
                       'a scan.'

        plain = f'{base_message}\n\n' \
                f'Unique Vulnerabilities: {unique_count}\n' \
                f'Total Vulnerabilities: {total_count}\n'

        content = Tag('div')

        content.append(Tag('p').append(base_message))

        results = {
                'Unique Vulnerabilities': unique_count,
                'Total Vulnerabilities': total_count
            }
        table = generate_html_table(results)
        content.append(table)

        document = generate_report_email_html(
                content,
                'Vulnerability Scan Results',
                hostname
            )

        return ReportEmail(
                recipient=recipient,
                subject=f'Vulnerability Scan Results for {hostname}',
                plain_content=plain,
                html_content=document.to_html()
            )


VULN_SCAN_REPORT_CONFIG_OPTIONS = get_config_options(
        VulnScanReportFormat,
        VulnScanReportColumn,
        default_format='human'
    )


class VulnScanReportManager(ReportManager):

    def __init__(
                self,
                context: CliContext,
                feed_variant: VulnerabilityFeedVariant
            ):
        super().__init__(
                formats=VulnScanReportFormat,
                columns=VulnScanReportColumn,
                context=context,
                read_stdin=context.config.read_stdin,
                input_delimiter=context.config.path_separator,
                binary_input=True
            )
        self.feed_variant = feed_variant

    def _instantiate_report(
                self,
                format: ReportFormat,
                columns: List[ReportColumn],
                email_addresses: List[str],
                mailer: Optional[Mailer],
                write_headers: bool
            ) -> VulnScanReport:
        for column in columns:
            if not column.is_compatible(self.feed_variant):
                raise ValueError(
                        f'Column {column.header} is not compatible '
                        'with the current feed'
                    )
        return VulnScanReport(
                format,
                columns,
                email_addresses,
                mailer,
                write_headers
            )
