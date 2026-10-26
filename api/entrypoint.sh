#!/bin/sh
set -eu

# The named volume mounts at /workspace root-owned on first run. Fix ownership so
# the API can write cases, then drop privileges to the non-root 'etherhawk' user.
mkdir -p /workspace/cases /workspace/_mitm
chown -R etherhawk:etherhawk /workspace 2>/dev/null || true
# The interactive browser container writes flows/artifacts as a different uid
# (kasm-user). Make the shared dirs writable by both on this single-tenant volume.
chmod 0777 /workspace /workspace/cases /workspace/_mitm 2>/dev/null || true

exec gosu etherhawk uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-access-log
