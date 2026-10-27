#!/usr/bin/env bash
# EtherHawk custom startup for kasmweb/chrome.
set -u

export DISPLAY="${DISPLAY:-:1}"
CDP_PORT="${CDP_PORT:-9222}"
PROFILE_DIR="/home/kasm-user/.config/eh-chrome"
mkdir -p "$PROFILE_DIR" /workspace/_mitm 2>/dev/null || true
touch /workspace/_mitm/flows.jsonl && chmod 666 /workspace/_mitm/flows.jsonl && chmod 777 /workspace/_mitm 2>/dev/null || true

# Use exact path to avoid matching Xvnc ('-DLP_ClipTypes chromium/x-web-custom-data' contains 'chrome')
pkill -9 -f '/opt/google/chrome/chrome' 2>/dev/null || true
sleep 2

# Use the real Chrome binary directly (the /usr/bin/google-chrome wrapper has
# a --user-data-dir bug that silently disables CDP remote debugging).
/opt/google/chrome/google-chrome \
  --no-sandbox \
  --ignore-gpu-blocklist \
  --remote-debugging-port="${CDP_PORT}" \
  --remote-debugging-address=127.0.0.1 \
  --remote-allow-origins='*' \
  --no-first-run --no-default-browser-check \
  --password-store=basic \
  --disable-session-crashed-bubble --disable-infobars \
  --start-maximized \
  --user-data-dir="$PROFILE_DIR" \
  about:blank >/tmp/eh-chrome.log 2>&1 &

cd /opt/etherhawk || exit 0
/opt/etherhawk/venv/bin/python -m uvicorn capture:app --host 0.0.0.0 --port 9001 --no-access-log \
  >/tmp/eh-capture.log 2>&1 &

exit 0
