#!/usr/bin/env bash
###############################################################################
# EtherHawk custom startup for kasmweb/chrome.
#
# kasmweb runs this hook (/dockerstartup/custom_startup.sh) after the desktop is
# up. We (1) launch Google Chrome ourselves with remote debugging enabled so the
# capture service can attach over CDP, on the Kasm display the analyst sees, and
# (2) start the capture/control service. Chrome keeps its genuine TLS fingerprint
# (no proxy), which is what lets us past server-side anti-analysis cloaking.
###############################################################################
set -u

export DISPLAY="${DISPLAY:-:1}"
CDP_PORT="${CDP_PORT:-9222}"
PROFILE_DIR="/home/kasm-user/.config/eh-chrome"
mkdir -p "$PROFILE_DIR" /workspace/_mitm 2>/dev/null || true
# Ensure the flows file is writable by the capture service (uid 1000 kasm-user)
touch /workspace/_mitm/flows.jsonl && chmod 666 /workspace/_mitm/flows.jsonl && chmod 777 /workspace/_mitm 2>/dev/null || true

# Set display resolution. VNC_RESOLUTION env is passed to vncserver -geometry but
# the kasmweb wrapper ignores it when the requested mode is not in its built-in
# default modelist (e.g. 1280x720). Force it here via xrandr after the X server
# is up so the analyst gets a proper 1920x1080 desktop regardless.
TARGET_RES="${VNC_RESOLUTION:-1920x1080}"
if xrandr --output VNC-0 --mode "$TARGET_RES" 2>/dev/null; then
    echo "EtherHawk: display set to $TARGET_RES"
else
    echo "EtherHawk: xrandr $TARGET_RES failed, staying at current resolution"
fi

# Stop any chrome the base image auto-started, so ours (with remote debugging)
# is the one the analyst sees and the one we attach to.
pkill -f "chrome" 2>/dev/null || true
sleep 2

CHROME_BIN="$(command -v google-chrome || command -v google-chrome-stable || command -v chromium || echo /usr/bin/google-chrome)"

"$CHROME_BIN" \
  --remote-debugging-port="${CDP_PORT}" \
  --remote-debugging-address=127.0.0.1 \
  --remote-allow-origins=* \
  --no-first-run --no-default-browser-check \
  --password-store=basic \
  --disable-session-crashed-bubble --disable-infobars \
  --start-maximized \
  --user-data-dir="$PROFILE_DIR" \
  "about:blank" >/tmp/eh-chrome.log 2>&1 &

# Start the EtherHawk capture/control service (attaches to Chrome over CDP).
cd /opt/etherhawk || exit 0
/opt/etherhawk/venv/bin/python -m uvicorn capture:app --host 0.0.0.0 --port 9001 --no-access-log \
  >/tmp/eh-capture.log 2>&1 &

# Return so kasm's session supervisor keeps running the desktop.
exit 0