#!/bin/sh
# Supervisor for radiusd. Everything it runs on is written by the admin panel into
# /etc/raddb/panel-dyn. A reload request is applied only if `radiusd -C` passes;
# otherwise the running server keeps its old config (or waits for a valid one).
PATH=/opt/sbin:/opt/bin:$PATH
DYN=/etc/raddb/panel-dyn
LOG=/var/log/wifi-redis
CTL=/var/run/wifi-redis-control
MAX_LOG=20971520   # 20 MB
umask 022
mkdir -p "$LOG" "$CTL"
touch "$LOG/auth.log" "$LOG/redis.log"

PID=""; SINCE=0; RELOAD_AT=$(date +%s); RELOAD_OK=false; RESTARTS=0; WANT=false
args() { case "$(head -c 8 "$DYN/radiusd-args" 2>/dev/null | tr -d '\n ')" in -xx) echo "-xx";; *) echo "";; esac; }
check() {
  if out=$(radiusd -C -l stdout 2>&1); then RELOAD_OK=true; : > "$CTL/reload.error"; return 0; fi
  RELOAD_OK=false
  echo "$out" | grep -iE "error|fail|unable|no such" | grep -v "^$" | tail -12 > "$CTL/reload.error"
  [ -s "$CTL/reload.error" ] || echo "$out" | tail -12 > "$CTL/reload.error"
  return 1
}
start() { radiusd -f -l "$LOG/redis.log" $(args) & PID=$!; SINCE=$(date +%s); WANT=true; }
stop() { if [ -n "$PID" ]; then kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; fi; PID=""; }
running() { [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; }
write_status() {
  if running; then state=running; elif $WANT; then state=restarting; else state=waiting; fi
  printf '{"state":"%s","pid":%s,"since":%s,"reload_at":%s,"reload_ok":%s,"restarts":%s,"updated":%s}\n' \
    "$state" "${PID:-0}" "$SINCE" "$RELOAD_AT" "$RELOAD_OK" "$RESTARTS" "$(date +%s)" > "$CTL/status.json.tmp"
  mv "$CTL/status.json.tmp" "$CTL/status.json"
}
rotate() {
  for f in "$LOG/auth.log" "$LOG/redis.log"; do
    if [ "$(wc -c < "$f")" -gt "$MAX_LOG" ]; then cp "$f" "$f.1" && : > "$f"; fi
  done
  chmod 644 "$LOG"/*.log* 2>/dev/null
}
trap 'stop; exit 0' TERM INT

tail -n 0 -F "$LOG/redis.log" 2>/dev/null &   # mirror to `docker logs`
if check; then start; else echo "Waiting for a valid configuration from the admin panel"; cat "$CTL/reload.error"; fi
write_status

while true; do
  sleep 2
  if [ -f "$CTL/reload.request" ]; then
    rm -f "$CTL/reload.request"; RELOAD_AT=$(date +%s)
    if check; then echo "Config check OK - (re)starting radiusd"; stop; start
    else echo "Config check FAILED - keeping the current state"; cat "$CTL/reload.error"; fi
  fi
  if $WANT && ! running; then
    echo "radiusd stopped - restarting"; RESTARTS=$((RESTARTS+1)); sleep 3
    if check; then start; else WANT=false; fi
  fi
  rotate; write_status
done
