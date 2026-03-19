#!/bin/bash
# Flywheel Security Scanner
# Combines malware scanning and vulnerability checking in a single tool.
# Usage: bash <(curl -sL https://raw.githubusercontent.com/wpelucas/fw-scanner/main/scan.sh) [LICENSE_KEY]

set -euo pipefail

LICENSE="${1:-faba755939fba9e467203a1a40cb39702b3c3b2a5643e84c2d7622bf3c577a4cb850cdbd1ab61ffdd4db4d669407e0d21c3e0d71bcf99af895bb0a67fdf87c091494eb12b3fec30fd69563eaeb5a86d1}"
REPO="https://github.com/wpelucas/fw-scanner.git"
INSTALL_DIR="fw-scanner"
DATE=$(date +"%m-%d-%Y-%T")
MALWARE_CSV="malware-results-$DATE.csv"
VULN_CSV="vuln-results-$DATE.csv"
FINAL_CSV="scan-results-$DATE.csv"

# Boot animation
BOOT_MSG='Booting up security scanner'
echo -ne "$BOOT_MSG"
while true; do echo -ne "."; sleep 0.5; done &
BOOTING_PID=$!

# Install dependencies and clone/update repo
sudo apt-get update -qq > /dev/null 2>&1
sudo apt-get install -qq git python3-pip -y > /dev/null 2>&1
sudo pip3 install packaging requests pymysql > /dev/null 2>&1

if [ -d "$INSTALL_DIR" ]; then
    cd "$INSTALL_DIR" && git pull > /dev/null 2>&1 && cd ..
else
    git clone "$REPO" > /dev/null 2>&1
fi

# Install the combined package once
sudo pip3 install "./$INSTALL_DIR" > /dev/null 2>&1

kill $BOOTING_PID 2>/dev/null || true
echo -ne "\r\e[K"

# Run malware scan
sudo python3 "$INSTALL_DIR/main.py" malware-scan / \
    --license "$LICENSE" \
    --images \
    --purge-cache \
    --workers=8 \
    --quiet \
    --output \
    --output-path "$MALWARE_CSV" \
    --output-columns filename,signature_description

# Run vulnerability scan
sudo python3 "$INSTALL_DIR/main.py" vuln-scan / \
    --license "$LICENSE" \
    --output \
    --output-path "$VULN_CSV"

# Process results
MALWARE_MATCHES=$(grep -c -e "/www" -e "/staging" "$MALWARE_CSV" 2>/dev/null || echo 0)
VULN_MATCHES=$(grep -c "<=" "$VULN_CSV" 2>/dev/null || echo 0)

if [ "$MALWARE_MATCHES" -gt 0 ] || [ "$VULN_MATCHES" -gt 0 ]; then
    echo "" | sudo tee -a "$MALWARE_CSV" > /dev/null
    cat "$MALWARE_CSV" "$VULN_CSV" > "$FINAL_CSV"
    echo -e "Security scan completed \033[0;38;5;7m- Report saved in $FINAL_CSV\033[0m\n"
    sudo rm -f "$MALWARE_CSV" "$VULN_CSV"
else
    echo -e "Security scan completed \033[0;38;5;7m- No report saved, site appears clean\033[0m\n"
    sudo rm -f "$MALWARE_CSV" "$VULN_CSV"
fi

# Cleanup
sudo rm -rf "$INSTALL_DIR" > /dev/null 2>&1
