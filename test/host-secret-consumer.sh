#!/usr/bin/env bash
# HostSecrets_test.pl uses this script as the program of a test consumer unit. The unit reads
# TEST_API_KEY from its environment file. The script fails while $STATE_DIR/fail exists, waits
# while $STATE_DIR/hold exists, and writes the SHA-256 of the received value to
# $STATE_DIR/received.
set -euo pipefail

STATE_DIR="$1"

if [[ -e "$STATE_DIR/fail" ]]; then
    exit 1
fi
while [[ -e "$STATE_DIR/hold" ]]; do
    sleep 0.2
done
printf '%s' "${TEST_API_KEY:-}" | sha256sum | cut -d ' ' -f 1 > "$STATE_DIR/received"
