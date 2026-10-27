#!/usr/bin/env bash
# EtherHawk custom startup — launched by KasmVNC's vnc_startup.sh in background.
# MUST NOT exit early: KasmVNC records this bash PID in KASM_PROCS['custom_startup']
# and checks it every 3 s; an early exit produces "Unknown Service: custom_startup" spam.
set -u

export DISPLAY="${DISPLAY:-:1}"
CDP_PORT="${CDP_PORT:-9222}"
CHROME_BIN="/opt/google/chrome/google-chrome"
PROFILE_DIR="/home/kasm-user/.config/eh-chrome"

mkdir -p "$PROFILE_DIR" /workspace/_mitm 2>/dev/null || true
touch /workspace/_mitm/flows.jsonl \
  && chmod 666 /workspace/_mitm/flows.jsonl \
  && chmod 777 /workspace/_mitm 2>/dev/null || true

CHROME_PID=""

if pgrep -f "$CHROME_BIN" >/dev/null 2>&1; then
  echo "EtherHawk: Chrome already running -- skipping start." >&2
  CHROME_PID="$(pgrep -f "$CHROME_BIN" | head -1)"
else
  # Kill any stale Chrome processes (zygote, GPU, crashpad, etc.) from previous runs.
  # Pattern 'opt/google/chrome' (no leading /) matches google-chrome AND chrome children.
  # NEVER pkill 'chromium' -- Xvnc cmdline has '-DLP_ClipTypes chromium/x-web-custom-data'
  # and pkill -f chromium would kill the VNC server, crashing the container.
  pkill -9 -f 'opt/google/chrome' 2>/dev/null || true
  sleep 2
  rm -rf "$PROFILE_DIR"
  mkdir -p "$PROFILE_DIR"

  "$CHROME_BIN" \
    --no-sandbox \
    --ignore-gpu-blocklist \
    --disable-blink-features=AutomationControlled \
    --remote-debugging-port="${CDP_PORT}" \
    --remote-debugging-address=127.0.0.1 \
    --remote-allow-origins='*' \
    --no-first-run --no-default-browser-check \
    --password-store=basic \
    --disable-session-crashed-bubble --disable-infobars \
    --start-maximized \
    --user-data-dir="$PROFILE_DIR" \
    about:blank >/tmp/eh-chrome.log 2>&1 &
  CHROME_PID=$!
fi

if ! pgrep -f 'uvicorn capture:app' >/dev/null 2>&1; then
  cd /opt/etherhawk
  /opt/etherhawk/venv/bin/python -m uvicorn capture:app \
    --host 0.0.0.0 --port 9001 --no-access-log \
    >/tmp/eh-capture.log 2>&1 &
fi

# Block here so the KasmVNC watchdog sees this process alive and stops logging
# "Unknown Service: custom_startup" every 3 s.
# wait works for our own child; the pgrep loop covers the already-running case.
if [ -n "${CHROME_PID:-}" ]; then
  wait "$CHROME_PID" 2>/dev/null || true
fi
while pgrep -f "$CHROME_BIN" >/dev/null 2>&1; do
  sleep 10
done