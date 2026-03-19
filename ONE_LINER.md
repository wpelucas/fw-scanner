# One-Liner Security Scanner

## Using scan.sh (recommended)
```bash
bash <(curl -sL https://raw.githubusercontent.com/wpelucas/fw-scanner/main/scan.sh)
```

## One-liner equivalent
```bash
(clear; BOOT_MSG='Booting up security scanner'; echo -ne "$BOOT_MSG"; while true; do echo -ne "."; sleep 0.5; done & BOOTING_PID=$!; sudo apt-get update -qq > /dev/null 2>&1 && sudo apt-get install -qq git python3-pip -y > /dev/null 2>&1 && sudo pip3 install packaging requests pymysql > /dev/null 2>&1 && (cd fw-scanner 2>/dev/null && git pull > /dev/null 2>&1 || git clone https://github.com/wpelucas/fw-scanner.git > /dev/null 2>&1) && sudo pip3 install ./fw-scanner > /dev/null 2>&1; kill $BOOTING_PID; echo -ne "\r\e[K"; DATE=$(date +"%m-%d-%Y-%T"); MALWARE_CSV="malware-results-$DATE.csv"; VULN_CSV="vuln-results-$DATE.csv"; FINAL_CSV="scan-results-$DATE.csv"; sudo python3 fw-scanner/main.py malware-scan / --license faba755939fba9e467203a1a40cb39702b3c3b2a5643e84c2d7622bf3c577a4cb850cdbd1ab61ffdd4db4d669407e0d21c3e0d71bcf99af895bb0a67fdf87c091494eb12b3fec30fd69563eaeb5a86d1 --images --purge-cache --workers=8 --quiet --output --output-path $MALWARE_CSV --output-columns filename,signature_description && sudo python3 fw-scanner/main.py vuln-scan / --license faba755939fba9e467203a1a40cb39702b3c3b2a5643e84c2d7622bf3c577a4cb850cdbd1ab61ffdd4db4d669407e0d21c3e0d71bcf99af895bb0a67fdf87c091494eb12b3fec30fd69563eaeb5a86d1 --output --output-path $VULN_CSV; MALWARE_MATCHES=$(grep -c -e "/www" -e "/staging" $MALWARE_CSV 2>/dev/null || echo 0); VULN_MATCHES=$(grep -c "<=" $VULN_CSV 2>/dev/null || echo 0); if [ $MALWARE_MATCHES -gt 0 ] || [ $VULN_MATCHES -gt 0 ]; then echo "" | sudo tee -a $MALWARE_CSV > /dev/null; cat $MALWARE_CSV $VULN_CSV > $FINAL_CSV; echo -e "Security scan completed \033[0;38;5;7m- Report saved in $FINAL_CSV\033[0m\n"; sudo rm -f $MALWARE_CSV $VULN_CSV; else echo -e 'Security scan completed \033[0;38;5;7m- No report saved, site appears clean\033[0m\n'; sudo rm -f $MALWARE_CSV $VULN_CSV; fi; sudo rm -rf fw-scanner > /dev/null 2>&1)
```

## Key improvements over the old two-repo setup
- Single repo (`fw-scanner`) instead of separate `malware-scanner` and `vuln-scanner` repos
- Single `pip install` instead of two separate installs
- Both `malware-scan` and `vuln-scan` commands available from the same package
- Updated to Wordfence CLI v5.0.3 (from v1.1.0/v2.0.2)
- All Flywheel-specific customizations preserved
