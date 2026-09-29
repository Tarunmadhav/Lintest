#!/usr/bin/env bash
# =============================================================================
#  LinTest installer
#  Installs the monitor, its dependencies, and the systemd timer.
#
#  Usage:
#    sudo ./install.sh                     # full install + systemd timer
#    sudo ./install.sh --cron              # install cron instead of systemd
#    sudo ./install.sh --no-schedule       # install files only
#    ./install.sh --uninstall              # remove everything again
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/lintest"
LOG_DIR="/var/log/lintest"
STATE_DIR="/var/lib/lintest"
SERVICE_USER="lintest"
VENV_DIR="$INSTALL_DIR/.venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

CRON_MODE=0
NO_SCHEDULE=0
UNINSTALL=0

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR\033[0m %s\n' "$*" >&2; exit 1; }

# -----------------------------------------------------------------------------
# Parse arguments
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cron)       CRON_MODE=1 ;;
        --no-schedule) NO_SCHEDULE=1 ;;
        --uninstall)  UNINSTALL=1 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
done

# -----------------------------------------------------------------------------
# Uninstall
# -----------------------------------------------------------------------------
if [[ $UNINSTALL -eq 1 ]]; then
    log "disabling and removing timer/service"
    systemctl disable --now lintest.timer 2>/dev/null || true
    rm -f /etc/systemd/system/lintest.timer /etc/systemd/system/lintest.service
    systemctl daemon-reload 2>/dev/null || true
    log "removing cron entry"
    crontab -u "$SERVICE_USER" -r 2>/dev/null || true
    log "removing $INSTALL_DIR (config preserved at $INSTALL_DIR/config.yaml.bak if present)"
    [[ -f $INSTALL_DIR/config.yaml ]] && cp -f "$INSTALL_DIR/config.yaml" /tmp/lintest-config.yaml.bak
    rm -rf "$INSTALL_DIR"
    [[ -f /tmp/lintest-config.yaml.bak ]] && mv /tmp/lintest-config.yaml.bak "$INSTALL_DIR/config.yaml.bak" 2>/dev/null || true
    log "LinTest uninstalled (logs kept in $LOG_DIR)"
    exit 0
fi

# -----------------------------------------------------------------------------
# Preflight
# -----------------------------------------------------------------------------
[[ $(id -u) -eq 0 ]] || die "run with sudo (needs $INSTALL_DIR, systemd and user creation)"
[[ -f lintest/main.py && -f config.yaml ]] || die "run this script from the repository root"
command -v "$PYTHON_BIN" >/dev/null || die "$PYTHON_BIN not found -- set PYTHON_BIN=/path/to/python3"
"$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
    || die "Python 3.10+ required"

# -----------------------------------------------------------------------------
# User, directories, files
# -----------------------------------------------------------------------------
log "creating service user '$SERVICE_USER' (system, no login)"
id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin "$SERVICE_USER"

log "creating directories"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" "$LOG_DIR" "$STATE_DIR" "$INSTALL_DIR"

log "copying application to $INSTALL_DIR"
rsync -a --delete \
    --exclude '.git' --exclude '.venv' --exclude '__pycache__' \
    --exclude '.pytest_cache' --exclude 'tests' --exclude '.env' \
    ./ "$INSTALL_DIR/"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"

# -----------------------------------------------------------------------------
# Virtualenv + dependencies
# -----------------------------------------------------------------------------
log "creating virtualenv and installing dependencies"
"$PYTHON_BIN" -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip --quiet
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" --quiet
chown -R "$SERVICE_USER":"$SERVICE_USER" "$VENV_DIR"

# -----------------------------------------------------------------------------
# Secrets (.env with Telegram credentials)
# -----------------------------------------------------------------------------
if [[ ! -f $INSTALL_DIR/.env ]]; then
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    chmod 600 "$INSTALL_DIR/.env"
    chown "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR/.env"
    warn "created $INSTALL_DIR/.env -- EDIT IT and set LINTEST_TELEGRAM_TOKEN / LINTEST_TELEGRAM_CHAT_ID"
fi

# Smoke test as the service user
log "running smoke test (config load)"
sudo -u "$SERVICE_USER" "$VENV_DIR/bin/lintest" --config "$INSTALL_DIR/config.yaml" --help >/dev/null \
    || die "smoke test failed"

# -----------------------------------------------------------------------------
# Scheduling
# -----------------------------------------------------------------------------
if [[ $NO_SCHEDULE -eq 0 && $CRON_MODE -eq 0 ]]; then
    if command -v systemctl >/dev/null && systemctl is-system-running >/dev/null 2>&1; then
        log "installing systemd service + timer (every 5 minutes)"
        install -m 644 "$INSTALL_DIR/systemd/lintest.service" /etc/systemd/system/lintest.service
        install -m 644 "$INSTALL_DIR/systemd/lintest.timer"   /etc/systemd/system/lintest.timer
        systemctl daemon-reload
        systemctl enable --now lintest.timer
        systemctl list-timers lintest.timer --no-pager || true
    else
        warn "systemd not available -- falling back to cron"
        CRON_MODE=1
    fi
fi

if [[ $NO_SCHEDULE -eq 0 && $CRON_MODE -eq 1 ]]; then
    log "installing cron entry (every 5 minutes)"
    touch "/var/spool/cron/crontabs/$SERVICE_USER" 2>/dev/null || true
    ( crontab -u "$SERVICE_USER" -l 2>/dev/null | grep -v 'lintest' ; \
      sed "s|^# ||; /^$/d" "$INSTALL_DIR/cron/lintest.cron" ) | crontab -u "$SERVICE_USER" -
fi

log "done. Next steps:"
echo "    1. edit $INSTALL_DIR/.env  (Telegram token + chat id)"
echo "    2. edit $INSTALL_DIR/config.yaml (thresholds, services, hosts)"
echo "    3. test one pass:  sudo -u $SERVICE_USER $VENV_DIR/bin/lintest --config $INSTALL_DIR/config.yaml --once"
echo "    4. logs: journalctl -u lintest.service | tail -f  (or $LOG_DIR/lintest.log)"
