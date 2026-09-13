#!/usr/bin/env bash
# deploy.sh — ghostpay go-live: pull a named branch into /opt/ghostpay, npm ci, point the
# ghostpay systemd unit at /opt/ghostpay (with /opt/ghostpay/ghostpay.env), restart, and
# health-check /health + /. Any failure rolls the unit back to /root/ghostpay and reports.
#
#   ./deploy.sh <branch>              from a Mac: run the whole deploy over ssh ($VPS_HOST)
#   ./deploy.sh <branch> --on-vps     run directly on the VPS as root
#   ./deploy.sh <branch> --local      local prep only: git pull + npm ci + syntax check
#
# Sends no transactions. Never prints the contents of ghostpay.env.
set -euo pipefail

VPS_HOST="${VPS_HOST:-root@80.78.19.4}"

usage() {
  echo "usage: $0 <branch> [--local | --on-vps]" >&2
  echo "  default: deploy <branch> on $VPS_HOST over ssh (override with VPS_HOST=user@host)" >&2
}

BRANCH=""
MODE="ssh"
for arg in "$@"; do
  case "$arg" in
    --local) MODE="local" ;;
    --on-vps) MODE="vps" ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "deploy: unknown flag $arg" >&2; usage; exit 1 ;;
    *) if [ -z "$BRANCH" ]; then BRANCH="$arg"; else echo "deploy: unexpected extra argument: $arg" >&2; usage; exit 1; fi ;;
  esac
done
if [ -z "$BRANCH" ]; then echo "deploy: branch name required" >&2; usage; exit 1; fi

step() { echo; echo "== $*"; }

local_prep() {
  step "fetch + checkout $BRANCH (local)"
  git fetch origin "$BRANCH"
  CURRENT="$(git rev-parse --abbrev-ref HEAD)"
  if [ "" != "" ]; then git checkout -B "" FETCH_HEAD 2>/dev/null || git checkout ""; fi
  git pull --ff-only origin "$BRANCH"
  step "npm ci"
  npm ci
  step "syntax check"
  for f in serve.mjs monitor.mjs notify.mjs fees.mjs; do
    node --check "$f"
    echo "ok: $f"
  done
  step "local prep done"
}

# the remote half, piped to bash over ssh (or run locally with --on-vps)
remote_script() {
  cat <<'REMOTE'
#!/usr/bin/env bash
set -euo pipefail

BRANCH="$1"
APP_DIR=/opt/ghostpay
FALLBACK_DIR=/root/ghostpay
SERVICE=ghostpay
PORT="${PORT:-8791}"
NODE_BIN="$(command -v node)"

step() { echo; echo "== $*"; }

# points the unit at $1 via a drop-in override. EnvironmentFile entries are read in
# order, so the drop-in's ghostpay.env wins over any older one in the base unit; the
# empty ExecStart= line clears the base unit's command before setting the new one.
write_unit() {
  local dir="$1"
  mkdir -p "/etc/systemd/system/$SERVICE.service.d"
  cat > "/etc/systemd/system/$SERVICE.service.d/10-ghostpay-paths.conf" <<UNIT
# written by deploy.sh ($(date -u +%Y-%m-%dT%H:%M:%SZ)): relayer runs from $dir
[Service]
WorkingDirectory=$dir
EnvironmentFile=$dir/ghostpay.env
ExecStart=
ExecStart=$NODE_BIN $dir/serve.mjs
UNIT
  systemctl daemon-reload
}

health_check() {
  local tries=0
  while [ "$tries" -lt 12 ]; do
    if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null && curl -fsS "http://127.0.0.1:$PORT/" >/dev/null; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 5
  done
  return 1
}

step "pull $BRANCH into $APP_DIR"
cd "$APP_DIR"
git fetch origin "$BRANCH"
CURRENT="$(git rev-parse --abbrev-ref HEAD)"
if [ "" != "" ]; then git checkout -B "" FETCH_HEAD 2>/dev/null || git checkout ""; fi
git pull --ff-only origin "$BRANCH"

step "npm ci"
npm ci

step "syntax check"
"$NODE_BIN" --check serve.mjs

if [ ! -f "$APP_DIR/ghostpay.env" ]; then
  echo "deploy: $APP_DIR/ghostpay.env missing — the relayer needs its env file, aborting (unit untouched)" >&2
  exit 1
fi

step "point $SERVICE at $APP_DIR"
write_unit "$APP_DIR"

step "restart $SERVICE"
systemctl restart "$SERVICE"

if health_check; then
  echo
  echo "deploy OK: $SERVICE is serving $BRANCH from $APP_DIR on port $PORT"
  curl -fsS "http://127.0.0.1:$PORT/health"
  echo
  exit 0
fi

echo
echo "deploy FAILED: $APP_DIR build did not pass the health check — rolling back to $FALLBACK_DIR" >&2
write_unit "$FALLBACK_DIR"
systemctl restart "$SERVICE"
if health_check; then
  echo "rollback OK: $SERVICE is back on $FALLBACK_DIR" >&2
else
  echo "rollback FAILED: $SERVICE unhealthy on both $APP_DIR and $FALLBACK_DIR" >&2
  echo "investigate: journalctl -u $SERVICE -n 100 --no-pager" >&2
fi
exit 1
REMOTE
}

case "$MODE" in
  local)
    local_prep
    ;;
  vps)
    if [ "$(id -u)" != "0" ]; then echo "deploy: --on-vps must run as root" >&2; exit 1; fi
    remote_script | bash -s -- "$BRANCH"
    ;;
  ssh)
    echo "deploy: running on $VPS_HOST over ssh (branch $BRANCH)"
    remote_script | ssh "$VPS_HOST" bash -s -- "$BRANCH"
    ;;
esac
