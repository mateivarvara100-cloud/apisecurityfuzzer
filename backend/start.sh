#!/bin/sh
# Render's start command (render.yaml): the VulnShop lab and the API, in one service.
#
# The lab is deliberately vulnerable, so it listens on 127.0.0.1 only: the scanner in this
# service reaches it, the internet never does (the same rule as docker-compose.yml). If it stops,
# it is started again. The API runs in the foreground, on the port Render gives in PORT.
#
# Locally (from Git Bash or any shell), after `uv sync` in backend/:
#   API_HOST=127.0.0.1 LAB_PORT=8011 LAB_URL=http://127.0.0.1:8011 PORT=8012 sh backend/start.sh
set -eu
cd "$(dirname "$0")"  # backend/, so a local .env here is read; Render has none and uses its settings

PY=.venv/bin/python
[ -x "$PY" ] || PY=.venv/Scripts/python.exe  # a Windows checkout

LAB_PORT="${LAB_PORT:-8000}"  # must match LAB_URL (default http://127.0.0.1:8000)
(
  while :; do
    DEMO_MODE=1 HOST=127.0.0.1 PORT="$LAB_PORT" SPEC_PATH=../lab/openapi.json "$PY" ../lab/app.py || true
    echo "start.sh: the lab stopped; starting it again" >&2
    sleep 1
  done
) &

# Render needs 0.0.0.0; API_HOST=127.0.0.1 keeps a local try-out off your network.
exec "$PY" -m uvicorn apifuzz_web.main:app --host "${API_HOST:-0.0.0.0}" --port "${PORT:?Render sets PORT}"
