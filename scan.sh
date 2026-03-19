#!/bin/bash
# Flywheel Security Scanner
# Combines malware scanning, vulnerability checking, database scanning, and remediation.
# Usage: bash <(curl -sL https://raw.githubusercontent.com/wpelucas/fw-scanner/main/scan.sh) [LICENSE_KEY]

set -euo pipefail

LICENSE="${1:-faba755939fba9e467203a1a40cb39702b3c3b2a5643e84c2d7622bf3c577a4cb850cdbd1ab61ffdd4db4d669407e0d21c3e0d71bcf99af895bb0a67fdf87c091494eb12b3fec30fd69563eaeb5a86d1}"
REPO="https://github.com/wpelucas/fw-scanner.git"
INSTALL_DIR="fw-scanner"
DATE=$(date +"%m-%d-%Y-%T")
MALWARE_CSV="malware-results-$DATE.csv"
VULN_CSV="vuln-results-$DATE.csv"
DBSCAN_CSV="dbscan-results-$DATE.csv"
FINAL_CSV="scan-results-$DATE.csv"

# Spinner with elapsed time for scans without built-in progress
spin_with_timer() {
    local label="$1"
    local pid="$2"
    local chars='|/-\'
    local start=$SECONDS
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        local elapsed=$(( SECONDS - start ))
        local mins=$(( elapsed / 60 ))
        local secs=$(( elapsed % 60 ))
        printf "\r  %s %s [%02d:%02d]" "${chars:i++%4:1}" "$label" "$mins" "$secs"
        sleep 0.25
    done
    local elapsed=$(( SECONDS - start ))
    local mins=$(( elapsed / 60 ))
    local secs=$(( elapsed % 60 ))
    printf "\r\e[K  ✓ %s [%02d:%02d]\n" "$label" "$mins" "$secs"
}

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

echo "Starting security scan..."
echo ""

# Run malware scan (uses built-in curses progress UI)
sudo python3 "$INSTALL_DIR/main.py" malware-scan / \
    --license "$LICENSE" \
    --images \
    --purge-cache \
    --workers=8 \
    --progress \
    --output \
    --output-path "$MALWARE_CSV" \
    --output-columns filename,signature_description

# Run vulnerability scan (with spinner + elapsed timer)
sudo python3 "$INSTALL_DIR/main.py" vuln-scan / \
    --license "$LICENSE" \
    --quiet \
    --output \
    --output-path "$VULN_CSV" &
VULN_PID=$!
spin_with_timer "Vulnerability scan" "$VULN_PID"
wait "$VULN_PID" || true

# Run database scan (with spinner + elapsed timer)
sudo python3 "$INSTALL_DIR/main.py" db-scan \
    --license "$LICENSE" \
    --locate-sites \
    --quiet \
    --output \
    --output-path "$DBSCAN_CSV" \
    --allow-io-errors / &
DBSCAN_PID=$!
spin_with_timer "Database scan" "$DBSCAN_PID"
wait "$DBSCAN_PID" || true

# Remediate malware findings
MALWARE_MATCHES=$(grep -c -e "/www" -e "/staging" "$MALWARE_CSV" 2>/dev/null || echo 0)
if [ "$MALWARE_MATCHES" -gt 0 ]; then
    grep -e "/www" -e "/staging" "$MALWARE_CSV" 2>/dev/null \
        | cut -d',' -f1 \
        | sudo python3 "$INSTALL_DIR/main.py" remediate \
            --read-stdin \
            --quiet \
            --output \
            --output-path "remediation-$DATE.csv" &
    REMED_PID=$!
    spin_with_timer "Remediating malware" "$REMED_PID"
    wait "$REMED_PID" || true
fi

# Process results
VULN_MATCHES=$(grep -c "<=" "$VULN_CSV" 2>/dev/null || echo 0)
DBSCAN_MATCHES=$(wc -l < "$DBSCAN_CSV" 2>/dev/null || echo 0)
DBSCAN_MATCHES=$(( DBSCAN_MATCHES > 1 ? DBSCAN_MATCHES - 1 : 0 ))  # subtract header

echo ""
if [ "$MALWARE_MATCHES" -gt 0 ] || [ "$VULN_MATCHES" -gt 0 ] || [ "$DBSCAN_MATCHES" -gt 0 ]; then
    echo "" | sudo tee -a "$MALWARE_CSV" > /dev/null
    cat "$MALWARE_CSV" "$VULN_CSV" "$DBSCAN_CSV" > "$FINAL_CSV" 2>/dev/null
    echo -e "Security scan completed \033[0;38;5;7m- Report saved in $FINAL_CSV\033[0m"
    [ -f "remediation-$DATE.csv" ] && echo -e "Remediation report \033[0;38;5;7m- saved in remediation-$DATE.csv\033[0m"
    echo ""
    sudo rm -f "$MALWARE_CSV" "$VULN_CSV" "$DBSCAN_CSV"
else
    echo -e "Security scan completed \033[0;38;5;7m- No report saved, site appears clean\033[0m\n"
    sudo rm -f "$MALWARE_CSV" "$VULN_CSV" "$DBSCAN_CSV"
fi

# Cleanup
sudo rm -rf "$INSTALL_DIR" > /dev/null 2>&1
