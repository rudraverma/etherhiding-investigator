#!/bin/sh
set -eu

# Live MITM proxy + web view for EtherHawk.
#  - proxy listens on :8095 (the browser + API route investigative traffic here)
#  - mitmweb UI on :8081 (optional raw view; the dashboard also renders flows natively)
#  - addon.py appends a structured JSON line per flow to $MITM_FLOWS_PATH
#
# Egress leaves via the Docker host's public IP (residential) unless UPSTREAM_PROXY
# is set — datacenter/VPN proxies suppress the EtherHiding eth_call, so default is
# direct host egress.

MODE_ARGS="--mode regular"
if [ -n "${UPSTREAM_PROXY:-}" ]; then
  echo "[etherhawk-proxy] routing egress via upstream proxy: ${UPSTREAM_PROXY}"
  MODE_ARGS="--mode upstream:${UPSTREAM_PROXY}"
fi

mkdir -p "$(dirname "${MITM_FLOWS_PATH:-/workspace/_mitm/flows.jsonl}")"

exec mitmweb \
  $MODE_ARGS \
  --listen-host 0.0.0.0 --listen-port 8095 \
  --web-host 0.0.0.0 --web-port 8081 \
  --set web_open_browser=false \
  --set connection_strategy=lazy \
  --set stream_large_bodies=5m \
  --ssl-insecure \
  -s /addon/addon.py
