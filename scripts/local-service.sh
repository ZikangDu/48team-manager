#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="local.team48.manager"
SERVICE="gui/$(id -u)/$LABEL"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
URL="http://127.0.0.1:8018"

is_loaded() {
  launchctl print "$SERVICE" >/dev/null 2>&1
}

check_health() {
  local attempt
  for attempt in {1..30}; do
    if is_loaded && /usr/bin/curl --noproxy '*' --fail --silent --max-time 2 "$URL/health" >/dev/null; then
      printf 'Team48 is ready at %s\n' "$URL"
      return 0
    fi
    sleep 1
  done
  printf 'Health check failed. See %s/logs/team48.stderr.log\n' "$ROOT" >&2
  return 1
}

start_service() {
  if ! is_loaded; then
    if [[ ! -f "$PLIST" ]]; then
      printf 'LaunchAgent is missing: %s\n' "$PLIST" >&2
      return 1
    fi
    if /usr/sbin/lsof -nP -iTCP:8018 -sTCP:LISTEN >/dev/null 2>&1; then
      printf 'Port 8018 is occupied. No process was stopped.\n' >&2
      return 1
    fi
    launchctl bootstrap "gui/$(id -u)" "$PLIST"
  fi
  check_health
}

stop_service() {
  local attempt
  if is_loaded; then
    launchctl bootout "$SERVICE"
    # bootout may return before the service and its listener have disappeared.
    for attempt in {1..30}; do
      if ! is_loaded && ! /usr/sbin/lsof -nP -iTCP:8018 -sTCP:LISTEN >/dev/null 2>&1; then
        printf 'Team48 is stopped for this login session.\n'
        return 0
      fi
      sleep 1
    done
    printf 'Team48 has not finished stopping. Check launchctl before restarting.\n' >&2
    return 1
  fi
  printf 'Team48 is stopped for this login session.\n'
}

case "${1:-status}" in
  start)
    start_service
    ;;
  stop)
    stop_service
    ;;
  restart)
    stop_service
    start_service
    ;;
  status)
    if ! is_loaded; then
      printf 'Team48 is not loaded.\n'
      exit 1
    fi
    launchctl print "$SERVICE" | /usr/bin/awk '/state =|pid =|last exit code =/'
    /usr/bin/curl --noproxy '*' --fail --silent --show-error --max-time 5 "$URL/health"
    printf '\n'
    ;;
  logs)
    exec /usr/bin/tail -n 80 "$ROOT/logs/team48.stderr.log"
    ;;
  *)
    printf 'Usage: %s {start|stop|restart|status|logs}\n' "$0" >&2
    exit 2
    ;;
esac
