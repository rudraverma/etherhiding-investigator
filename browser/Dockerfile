# Playwright's official image ships a matching Chromium + all browser OS deps + Xvfb.
FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY fingerprint.py behavior.py server.py hooks.js ./
COPY entrypoint.sh /usr/local/bin/etherhawk-browser-entrypoint.sh
RUN chmod +x /usr/local/bin/etherhawk-browser-entrypoint.sh

EXPOSE 9001

ENTRYPOINT ["/usr/local/bin/etherhawk-browser-entrypoint.sh"]
