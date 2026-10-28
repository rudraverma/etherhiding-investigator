# Interactive, analyst-drivable REAL Google Chrome (noVNC) with a CDP capture
# service. Chrome keeps its genuine TLS/HTTP2 fingerprint (no TLS-terminating
# proxy), which is what gets us past server-side anti-analysis cloaking.
FROM kasmweb/chrome:1.16.0

USER root

# Python + a venv for the capture service (avoids PEP668 on the base image).
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/etherhawk/venv \
    && /opt/etherhawk/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/etherhawk/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

COPY capture.py hooks.js /opt/etherhawk/
COPY custom_startup.sh /dockerstartup/custom_startup.sh

# The Kasm desktop runs as uid 1000 (kasm-user); make our files usable by it.
RUN chmod +x /dockerstartup/custom_startup.sh \
    && chown -R 1000:0 /opt/etherhawk \
    && chmod -R u+rwX,g+rwX /opt/etherhawk

# Fix noVNC session-timeout TypeError: UI.rfb is undefined before any viewer connects.
# Without this guard the setInterval fires, reads UI.rfb.lastActiveAt on undefined, throws,
# and the catch block shows a blocking modal over the analyst's desktop.
RUN grep -q 'UI.rfb.lastActiveAt) return' /usr/share/kasmvnc/www/dist/main.bundle.js \
    || sed -i \
       's/UI\._sessionTimeoutInterval = setInterval(function () {/UI._sessionTimeoutInterval = setInterval(function () { if (!UI.rfb || !UI.rfb.lastActiveAt) return;/' \
       /usr/share/kasmvnc/www/dist/main.bundle.js

# Do NOT override kasm's ENTRYPOINT/CMD -- it boots the desktop and then runs
# /dockerstartup/custom_startup.sh, which launches Chrome + the capture service.
USER 1000