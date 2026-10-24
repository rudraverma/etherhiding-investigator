#!/bin/bash
set -euo pipefail

# Run the worker under a virtual display so Chromium launches HEADFUL (not the
# trivially-fingerprinted headless-shell). A real headful browser is the hardest
# profile for an EtherHiding stage-1 gate to distinguish from a human's laptop.
exec xvfb-run -a --server-args="-screen 0 1920x1080x24 -ac +extension GLX +render -noreset" \
  uvicorn server:app --host 0.0.0.0 --port 9001 --no-access-log
