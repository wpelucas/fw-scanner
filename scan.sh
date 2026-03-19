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

# Elapsed time tracking for spinners
SPIN_ELAPSED=0

# Spinner with real-time progress percentage and ETA
spin_with_progress() {
    local label="$1"
    local pid="$2"
    local total="$3"
    local counter_file="$4"
    local chars='|/-\'
    local start=$SECONDS
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        local elapsed=$(( SECONDS - start ))
        local mins=$(( elapsed / 60 ))
        local secs=$(( elapsed % 60 ))
        local processed
        processed=$(cat "$counter_file" 2>/dev/null) || processed=0
        processed=${processed:-0}
        if [ "$total" -gt 0 ] && [ "$processed" -gt 100 ] && [ "$elapsed" -gt 3 ]; then
            local pct=$(( processed * 100 / total ))
            [ "$pct" -gt 99 ] && pct=99
            local rate_x10=$(( processed * 10 / elapsed ))
            if [ "$rate_x10" -gt 0 ]; then
                local remaining=$(( (total - processed) * 10 / rate_x10 ))
                local eta_mins=$(( remaining / 60 ))
                local eta_secs=$(( remaining % 60 ))
                printf "\r  %s %s [%d%%] [ETA %02d:%02d]   " "${chars:i++%4:1}" "$label" "$pct" "$eta_mins" "$eta_secs"
            else
                printf "\r  %s %s [%d%%] [%02d:%02d]   " "${chars:i++%4:1}" "$label" "$pct" "$mins" "$secs"
            fi
        else
            printf "\r  %s %s [%02d:%02d]   " "${chars:i++%4:1}" "$label" "$mins" "$secs"
        fi
        sleep 0.5
    done
    SPIN_ELAPSED=$(( SECONDS - start ))
    printf "\r\e[K"
}

# Spinner with elapsed time (for fast scans)
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
    SPIN_ELAPSED=$(( SECONDS - start ))
    printf "\r\e[K"
}

# Print scan status line with icon, label, time, and optional detail
# Usage: print_status "icon" "color" "label" elapsed "detail"
print_status() {
    local icon="$1" color="$2" label="$3" elapsed="$4" detail="${5:-}"
    local mins=$(( elapsed / 60 ))
    local secs=$(( elapsed % 60 ))
    if [ -n "$detail" ]; then
        printf "  %b%s%b %s [%02d:%02d] %b%s%b\n" "$color" "$icon" "\033[0m" "$label" "$mins" "$secs" "\033[0;38;5;7m" "$detail" "\033[0m"
    else
        printf "  %b%s%b %s [%02d:%02d]\n" "$color" "$icon" "\033[0m" "$label" "$mins" "$secs"
    fi
}

# Show banner
echo -e "\033[96m"
cat << 'BANNER'
         ▖▖▖▖▖▖▖  ▗
      ▖▞▝ ▖▖▖▖▖▝▝▖▖ ▖
    ▗▝ ▖▝▞    ▖▘▘▖▝▖ ▘
    ▌ ▌   ▘▖ ▗▖   ▚▝▚
   ▚ ▞▗ ▖▖▖▖▚ ▖ ▖▘▘▖▗▘  █▀▀ █░░ █▄█ █░█░█ █░█ █▀▀ █▀▀ █░░
  ▗▘▗▖ ▘ ▖▞▝ ▚ ▞   ▖ ▌  █▀░ █▄▄ ░█░ ▀▄▀▄▀ █▀█ ██▄ ██▄ █▄▄
   ▌ ▖  ▞ ▖▚▗▗▘▗▗▗ ▞ ▌
   ▚▖▘▘▘  ▚ ▚ ▘▘  ▚ ▐    S E C U R I T Y   S C A N N E R
    ▄ ▚   ▚  ▝▗  ▖ ▖▌
   ▖ ▚▗▝▘▖▘   ▝▖▘▗▐▝
    ▘▖▘▝▖▖▞▝▝▝▗▗▐▝
         ▝ ▘▘▘▘
BANNER
echo -e "\033[0m"

# Boot animation
BOOT_MSG='Booting up security scanner'
echo -ne "$BOOT_MSG"
while true; do echo -ne "."; sleep 0.5; done &
BOOTING_PID=$!

# Count files in parallel with dependency installation (for progress estimation)
COUNT_TMP=$(mktemp)
find / -type f \
    -not -path "/proc/*" \
    -not -path "/sys/*" \
    -not -path "/dev/*" \
    -not -path "/run/*" \
    2>/dev/null | wc -l > "$COUNT_TMP" &
COUNT_PID=$!

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

# Wait for file count to finish
wait "$COUNT_PID" 2>/dev/null || true
TOTAL_FILES=$(cat "$COUNT_TMP" 2>/dev/null) || TOTAL_FILES=0
TOTAL_FILES=${TOTAL_FILES:-0}
rm -f "$COUNT_TMP"

kill $BOOTING_PID 2>/dev/null || true
echo -ne "\r\e[K"

echo "Starting security scan..."
echo ""

# Run malware scan with progress tracking via verbose stderr output
# awk counts "Processing file:" lines and writes count to a temp file every 50 files
COUNTER_FILE=$(mktemp)
echo 0 > "$COUNTER_FILE"
{
    sudo python3 "$INSTALL_DIR/main.py" malware-scan / \
        --license "$LICENSE" \
        --images \
        --purge-cache \
        --workers=12 \
        --no-banner \
        --verbose \
        --output \
        --output-path "$MALWARE_CSV" \
        --output-columns filename,signature_description \
        2>&1 >/dev/null | \
    awk '/Processing file/{c++; if(c%50==0){printf "%d\n", c > "'"$COUNTER_FILE"'"; close("'"$COUNTER_FILE"'")}} END{if(c>0){printf "%d\n", c > "'"$COUNTER_FILE"'"; close("'"$COUNTER_FILE"'")}}'
} &
MALWARE_BG=$!
spin_with_progress "Malware scan" "$MALWARE_BG" "$TOTAL_FILES" "$COUNTER_FILE"
wait "$MALWARE_BG" || true
rm -f "$COUNTER_FILE"

# Check malware results and show status
MALWARE_MATCHES=$(grep -c -e "/www" -e "/staging" "$MALWARE_CSV" 2>/dev/null) || MALWARE_MATCHES=0
if [ "$MALWARE_MATCHES" -gt 0 ]; then
    print_status "⚠" "\033[0;31m" "Malware scan" "$SPIN_ELAPSED" "$MALWARE_MATCHES malicious file(s) found"
else
    print_status "✓" "\033[0;32m" "Malware scan" "$SPIN_ELAPSED" "Clean"
fi

# Run vulnerability scan (with spinner + elapsed timer)
sudo python3 "$INSTALL_DIR/main.py" vuln-scan / \
    --license "$LICENSE" \
    --no-banner \
    --quiet \
    --output \
    --output-path "$VULN_CSV" > /dev/null 2>&1 &
VULN_PID=$!
spin_with_timer "Vulnerability scan" "$VULN_PID"
wait "$VULN_PID" || true

# Check vulnerability results and show status
VULN_MATCHES=$(grep -c "<=" "$VULN_CSV" 2>/dev/null) || VULN_MATCHES=0
if [ "$VULN_MATCHES" -gt 0 ]; then
    print_status "⚠" "\033[0;33m" "Vulnerability scan" "$SPIN_ELAPSED" "$VULN_MATCHES vulnerable software found"
else
    print_status "✓" "\033[0;32m" "Vulnerability scan" "$SPIN_ELAPSED" "Clean"
fi

# Run database scan (with spinner + elapsed timer)
sudo python3 "$INSTALL_DIR/main.py" db-scan \
    --license "$LICENSE" \
    --locate-sites \
    --no-banner \
    --quiet \
    --output \
    --output-path "$DBSCAN_CSV" \
    --allow-io-errors / > /dev/null 2>&1 &
DBSCAN_PID=$!
spin_with_timer "Database scan" "$DBSCAN_PID"
wait "$DBSCAN_PID" || true

# Check database results and show status
DBSCAN_MATCHES=$(wc -l < "$DBSCAN_CSV" 2>/dev/null) || DBSCAN_MATCHES=0
DBSCAN_MATCHES=$(( DBSCAN_MATCHES > 1 ? DBSCAN_MATCHES - 1 : 0 ))  # subtract header
if [ "$DBSCAN_MATCHES" -gt 0 ]; then
    print_status "⚠" "\033[0;33m" "Database scan" "$SPIN_ELAPSED" "$DBSCAN_MATCHES finding(s)"
else
    print_status "✓" "\033[0;32m" "Database scan" "$SPIN_ELAPSED" "Clean"
fi

# Remediate malware findings
REMED_TOTAL=0
REMED_SUCCESS=0
REMED_FAILED=0
if [ "$MALWARE_MATCHES" -gt 0 ]; then
    REMED_CSV="remediation-$DATE.csv"
    grep -e "/www" -e "/staging" "$MALWARE_CSV" 2>/dev/null \
        | cut -d',' -f1 \
        | sudo python3 "$INSTALL_DIR/main.py" remediate \
            --read-stdin \
            --no-banner \
            --output \
            --output-headers \
            --output-path "$REMED_CSV" \
            --output-columns path,status,type > /dev/null 2>&1 &
    REMED_PID=$!
    spin_with_timer "Remediating malware" "$REMED_PID"
    wait "$REMED_PID" || true

    # Parse remediation results
    if [ -f "$REMED_CSV" ]; then
        REMED_SUCCESS=$(grep -c ",remediated," "$REMED_CSV" 2>/dev/null) || REMED_SUCCESS=0
        REMED_FAILED=$(grep -c -e ",failed," -e ",unrecognized," -e ",unidentified," "$REMED_CSV" 2>/dev/null) || REMED_FAILED=0
        REMED_TOTAL=$(( REMED_SUCCESS + REMED_FAILED ))
    fi

    if [ "$REMED_SUCCESS" -gt 0 ] && [ "$REMED_FAILED" -eq 0 ]; then
        print_status "✓" "\033[0;32m" "Remediation" "$SPIN_ELAPSED" "$REMED_SUCCESS/$REMED_TOTAL file(s) remediated"
    elif [ "$REMED_SUCCESS" -gt 0 ] && [ "$REMED_FAILED" -gt 0 ]; then
        print_status "⚠" "\033[0;33m" "Remediation" "$SPIN_ELAPSED" "$REMED_SUCCESS/$REMED_TOTAL remediated, $REMED_FAILED could not be remediated"
    elif [ "$REMED_TOTAL" -gt 0 ]; then
        print_status "✗" "\033[0;31m" "Remediation" "$SPIN_ELAPSED" "$REMED_FAILED file(s) could not be remediated (not from a known theme/plugin)"
    else
        print_status "✗" "\033[0;31m" "Remediation" "$SPIN_ELAPSED" "No files could be remediated"
    fi
fi

echo ""

# Display malware scan details
if [ "$MALWARE_MATCHES" -gt 0 ]; then
    echo -e "\033[1;31m── Malware Findings ($MALWARE_MATCHES) ──\033[0m"
    grep -e "/www" -e "/staging" "$MALWARE_CSV" 2>/dev/null | while IFS=',' read -r file desc rest; do
        # Determine remediation status for this file
        remed_icon="  \033[0;31m✗\033[0m"
        remed_note=""
        if [ -f "${REMED_CSV:-}" ]; then
            remed_line=$(grep "^$file," "$REMED_CSV" 2>/dev/null || true)
            if echo "$remed_line" | grep -q ",remediated,"; then
                remed_icon="  \033[0;32m✓\033[0m"
                remed_note=" \033[0;32m(remediated)\033[0m"
            elif echo "$remed_line" | grep -q ",unidentified,"; then
                remed_note=" \033[0;31m(not remediated - not a known theme/plugin)\033[0m"
            elif echo "$remed_line" | grep -q ",unrecognized,"; then
                remed_note=" \033[0;31m(not remediated - unrecognized version)\033[0m"
            elif echo "$remed_line" | grep -q ",failed,"; then
                remed_note=" \033[0;31m(not remediated - failed)\033[0m"
            fi
        fi
        echo -e "${remed_icon} ${file}${remed_note}"
        [ -n "$desc" ] && echo -e "    \033[0;38;5;7m$desc\033[0m"
    done
    echo ""
fi

# Display vulnerability scan details
if [ "$VULN_MATCHES" -gt 0 ]; then
    echo -e "\033[1;33m── Vulnerability Findings ($VULN_MATCHES) ──\033[0m"
    grep "<=" "$VULN_CSV" 2>/dev/null | while IFS=',' read -r slug version vuln_title rest; do
        echo -e "  \033[0;33m⚠\033[0m $slug ($version)"
        [ -n "$vuln_title" ] && echo -e "    \033[0;38;5;7m$vuln_title\033[0m"
    done
    echo ""
fi

# Display database scan details
if [ "$DBSCAN_MATCHES" -gt 0 ]; then
    echo -e "\033[1;33m── Database Findings ($DBSCAN_MATCHES) ──\033[0m"
    tail -n +2 "$DBSCAN_CSV" 2>/dev/null | while IFS=',' read -r line; do
        echo -e "  \033[0;33m⚠\033[0m $line"
    done
    echo ""
fi

# Save combined report
if [ "$MALWARE_MATCHES" -gt 0 ] || [ "$VULN_MATCHES" -gt 0 ] || [ "$DBSCAN_MATCHES" -gt 0 ]; then
    echo "" | sudo tee -a "$MALWARE_CSV" > /dev/null
    cat "$MALWARE_CSV" "$VULN_CSV" "$DBSCAN_CSV" > "$FINAL_CSV" 2>/dev/null
    echo -e "Security scan completed \033[0;38;5;7m- Report saved in $FINAL_CSV\033[0m"
    [ -f "${REMED_CSV:-}" ] && echo -e "Remediation report \033[0;38;5;7m- saved in $REMED_CSV\033[0m"
    echo ""
    sudo rm -f "$MALWARE_CSV" "$VULN_CSV" "$DBSCAN_CSV"
else
    echo -e "Security scan completed \033[0;38;5;7m- No report saved, site appears clean\033[0m\n"
    sudo rm -f "$MALWARE_CSV" "$VULN_CSV" "$DBSCAN_CSV"
fi

# Cleanup
sudo rm -rf "$INSTALL_DIR" > /dev/null 2>&1
