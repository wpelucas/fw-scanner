# One-Liner Security Scanner

## Using scan.sh (recommended)
```bash
bash <(curl -sL https://raw.githubusercontent.com/wpelucas/fw-scanner/main/scan.sh)
```

## Including the staging site
Only the production site is scanned by default. To scan `/staging` as well:
```bash
bash <(curl -sL https://raw.githubusercontent.com/wpelucas/fw-scanner/main/scan.sh) --staging
```

## With a custom license key
```bash
bash <(curl -sL https://raw.githubusercontent.com/wpelucas/fw-scanner/main/scan.sh) YOUR_LICENSE_KEY
```

## What it does
1. **Malware scan** - Scans all files with progress and ETA, using several workers per CPU core
2. **Vulnerability scan** - Checks WordPress installations for vulnerable software. Runs at the same time as the malware scan; its results are reported once the malware results are in
3. **Database scan** - Scans WordPress databases for malicious content via `--locate-sites` auto-discovery (spinner + elapsed timer)
4. **Remediation** - Automatically restores malware-infected files from WordPress.org (runs only if malware is found)

## Key improvements over the old two-repo setup
- Single repo (`fw-scanner`) instead of separate `malware-scanner` and `vuln-scanner` repos
- Single `pip install` instead of two separate installs
- All scan commands (`malware-scan`, `vuln-scan`, `db-scan`, `remediate`) available from the same package
- Updated to Wordfence CLI v5.0.3 (from v1.1.0/v2.0.2)
- Built-in progress UI for malware scan, spinner + elapsed timer for other scans
- Auto-remediation of detected malware
- All Flywheel-specific customizations preserved
