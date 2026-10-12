#!/usr/bin/env bash
# =============================================================================
#  LinTest installer
#  Installs the monitor, its dependencies, and a systemd timer (or cron entry).
#
#  Usage:
#    sudo ./install.sh                     # install + systemd timer
#    sudo ./install.sh --cron              # install + cron instead of systemd
#    sudo ./install.sh --no-schedule       # files only, no timer/cron
#    sudo ./install.sh --uninstall         # remove the program, keep config+logs
#    sudo ./install.sh --uninstall --purge # also remove logs, state and user
#
#  Re-running install.sh is safe and is how you upgrade: the existing
#  config.yaml and .env are preserved (the new config is written next to the
#  old one as config.yaml.new when it differs).
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/lintest"
LOG_DIR="/var/log/lintest"
STATE_DIR="/var/lib/lintest"
BACKUP_DIR="/var/backups/lintest"
SERVICE_USER="lintest"
VENV_DIR="$INSTALL_DIR/.venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

CRON_MODE=0
NO_SCHEDULE=0
UNINSTALL=0
PURGE=0

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR\033[0m %s\n' "$*" >&2; exit 1; }

# -----------------------------------------------------------------------------
# Parse arguments
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cron)        CRON_MODE=1 ;;
        --no-schedule) NO_SCHEDULE=1 ;;
        --uninstall)   UNINSTALL=1 ;;
        --purge)       PURGE=1 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
done

# -----------------------------------------------------------------------------
# Preflight (runs before *anything* else, including uninstall: every branch
# below needs root, and silently failing with '|| true' is how a half-removed
# install happens).
# -----------------------------------------------------------------------------
[[ $(id -u) -eq 0 ]] || die "run with sudo (needs $INSTALL_DIR, systemd and user creation)"

# -----------------------------------------------------------------------------
# Uninstall
# -----------------------------------------------------------------------------
if [[ $UNINSTALL -eq 1 ]]; then
    log "disabling and removing timer/service"
    systemctl disable --now lintest.timer 2>/dev/null || true
    systemctl stop lintest.service 2>/dev/null || true
    rm -f /etc/systemd/system/lintest.timer /etc/systemd/system/lintest.service
    systemctl daemon-reload 2>/dev/null || true

    log "removing cron entries (only LinTest's own lines)"
    if command -v crontab >/dev/null 2>&1; then
        if crontab -u "$SERVICE_USER" -l 2>/dev/null | grep -q 'lintest'; then
            # Drop only the LinTest marker block/line: never wipe a crontab
            # that may contain unrelated jobs.
            crontab -u "$SERVICE_USER" -l 2>/dev/null | grep -v 'lintest' \
                | crontab -u "$SERVICE_USER" - || warn "could not rewrite the $SERVICE_USER crontab"
        fi
    fi

    if [[ -f $INSTALL_DIR/config.yaml ]]; then
        install -d -m 750 "$BACKUP_DIR"
        backup="$BACKUP_DIR/config.yaml.$(date -u +%Y%m%dT%H%M%SZ)"
        install -m 600 "$INSTALL_DIR/config.yaml" "$backup"
        log "operator config preserved at $backup"
    fi

    log "removing $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"

    if [[ $PURGE -eq 1 ]]; then
        log "purging logs ($LOG_DIR) and state ($STATE_DIR)"
        rm -rf "$LOG_DIR" "$STATE_DIR"
        if id -u "$SERVICE_USER" >/dev/null 2>&1; then
            log "removing service user '$SERVICE_USER'"
            userdel "$SERVICE_USER" 2>/dev/null || warn "could not remove user $SERVICE_USER"
        fi
    else
        log "logs kept in $LOG_DIR, cooldown state kept in $STATE_DIR (use --purge to remove)"
    fi
    log "LinTest uninstalled"
    exit 0
fi

[[ -f lintest/main.py && -f config.yaml ]] || die "run this script from the repository root"
command -v "$PYTHON_BIN" >/dev/null || die "$PYTHON_BIN not found -- set PYTHON_BIN=/path/to/python3"
"$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
    || die "Python 3.10+ required"

# Run a command as the service user with a portable privilege dropper.
run_as_service_user() {
    local cmd="$*"
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "$SERVICE_USER" -- sh -c "$cmd"
    elif command -v sudo >/dev/null 2>&1; then
        sudo -u "$SERVICE_USER" -- sh -c "$cmd"
    else
        su -s /bin/sh -c "$cmd" "$SERVICE_USER"
    fi
}

# -----------------------------------------------------------------------------
# User, groups and directories
# -----------------------------------------------------------------------------
log "creating service user '$SERVICE_USER' (system account, no login shell)"
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --shell /usr/sbin/nologin --home-dir "$STATE_DIR" "$SERVICE_USER" \
        || useradd --system --shell /sbin/nologin --home-dir "$STATE_DIR" "$SERVICE_USER"
fi

# Log access: on Debian/Ubuntu /var/log/auth.log is 0640 root:adm, and reading
# the journal as a non-root user needs systemd-journal.  Without one of these
# the SSH-login check can only report "no auth source available".
for grp in adm systemd-journal; do
    if getent group "$grp" >/dev/null 2>&1; then
        if usermod -aG "$grp" "$SERVICE_USER" 2>/dev/null; then
            log "added $SERVICE_USER to group '$grp' (log access)"
        else
            warn "could not add $SERVICE_USER to group '$grp'"
        fi
    fi
done

log "creating directories"
install -d -m 755 -o root -g root "$INSTALL_DIR"
install -d -m 750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$LOG_DIR" "$STATE_DIR"

log "copying application to $INSTALL_DIR"
# config.yaml and .env are excluded on purpose: they belong to the operator and
# must survive an upgrade (`--delete` never removes excluded files).
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
        --exclude '.git' --exclude '.venv' --exclude '__pycache__' \
        --exclude '.pytest_cache' --exclude '.ruff_cache' --exclude 'tests' \
        --exclude '.env' --exclude 'config.yaml' \
        --exclude 'dist' --exclude 'build' --exclude '*.egg-info' \
        --exclude '.coverage' --exclude 'coverage.xml' --exclude '.github' \
        ./ "$INSTALL_DIR/"
else
    warn "rsync not found; falling back to cp"
    for entry in lintest systemd cron pyproject.toml requirements.txt \
                 requirements-dev.txt README.md CHANGELOG.md SECURITY.md \
                 install.sh .env.example config.yaml.example; do
        [[ -e $entry ]] && cp -a "$entry" "$INSTALL_DIR/"
    done
fi

# The application tree is owned by root: the service user may read it, but must
# not be able to rewrite the monitor's own code (the systemd unit additionally
# mounts it read-only via ProtectSystem=strict).
chown -R root:root "$INSTALL_DIR"
chmod -R go-w "$INSTALL_DIR"

if [[ -f $INSTALL_DIR/config.yaml ]]; then
    log "keeping the existing $INSTALL_DIR/config.yaml (upgrade-safe)"
    if [[ -f config.yaml ]] && ! cmp -s config.yaml "$INSTALL_DIR/config.yaml"; then
        install -m 644 -o root -g root config.yaml "$INSTALL_DIR/config.yaml.new"
        warn "a newer default config was written to $INSTALL_DIR/config.yaml.new -- diff it and merge"
    fi
else
    install -m 644 -o root -g root config.yaml "$INSTALL_DIR/config.yaml"
    log "installed default config to $INSTALL_DIR/config.yaml"
fi
chown root:root "$INSTALL_DIR/config.yaml"
chmod 644 "$INSTALL_DIR/config.yaml"

# -----------------------------------------------------------------------------
# Virtualenv + dependencies
# -----------------------------------------------------------------------------
log "creating virtualenv and installing the package"
"$PYTHON_BIN" -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip --quiet
# Install the package itself: this pulls in the runtime dependencies AND, unlike
# `pip install -r requirements.txt`, creates the `lintest` console script that
# the systemd unit's ExecStart and the smoke test below rely on.
"$VENV_DIR/bin/pip" install --quiet "$INSTALL_DIR"
[[ -x $VENV_DIR/bin/lintest ]] || die "installation failed: $VENV_DIR/bin/lintest was not created"
log "installed $("$VENV_DIR/bin/lintest" --version)"
"$VENV_DIR/bin/python" -m compileall -q "$INSTALL_DIR/lintest" >/dev/null 2>&1 || true

# -----------------------------------------------------------------------------
# Secrets (.env with Telegram credentials)
# -----------------------------------------------------------------------------
if [[ -f $INSTALL_DIR/.env ]]; then
    log "keeping the existing $INSTALL_DIR/.env"
    chown root:"$SERVICE_USER" "$INSTALL_DIR/.env"
    chmod 640 "$INSTALL_DIR/.env"
else
    install -m 640 -o root -g "$SERVICE_USER" "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    warn "created $INSTALL_DIR/.env -- EDIT IT and set LINTEST_TELEGRAM_TOKEN / LINTEST_TELEGRAM_CHAT_ID"
fi

# -----------------------------------------------------------------------------
# Smoke test: a real single pass as the service user (config validation +
# every enabled check, without dispatching alerts).
# -----------------------------------------------------------------------------
log "running smoke test (one check pass as $SERVICE_USER)"
set +e
smoke_output="$(run_as_service_user \
    "LINTEST_STATE_FILE=$STATE_DIR/state.json $VENV_DIR/bin/lintest --config $INSTALL_DIR/config.yaml --dry-run" 2>&1)"
smoke_rc=$?
set -e
printf '%s\n' "$smoke_output" | tail -20
# 0 = no criticals, 1 = at least one CRITICAL (expected on a busy/limited box)
(( smoke_rc <= 1 )) || die "smoke test failed (exit $smoke_rc)"
log "smoke test ok (exit $smoke_rc)"

# -----------------------------------------------------------------------------
# Scheduling
# -----------------------------------------------------------------------------
if [[ $NO_SCHEDULE -eq 0 && $CRON_MODE -eq 0 ]]; then
    if command -v systemctl >/dev/null && systemctl is-system-running >/dev/null 2>&1; then
        log "installing systemd service + timer (every 5 minutes)"
        install -m 644 -o root -g root "$INSTALL_DIR/systemd/lintest.service" /etc/systemd/system/lintest.service
        install -m 644 -o root -g root "$INSTALL_DIR/systemd/lintest.timer"   /etc/systemd/system/lintest.timer
        systemctl daemon-reload
        systemctl enable lintest.timer >/dev/null
        # restart (not just enable --now) so an upgrade picks up unit changes
        systemctl restart lintest.timer
        systemctl list-timers lintest.timer --no-pager || true
    else
        warn "systemd not available -- falling back to cron"
        CRON_MODE=1
    fi
fi

if [[ $NO_SCHEDULE -eq 0 && $CRON_MODE -eq 1 ]]; then
    if ! command -v crontab >/dev/null 2>&1; then
        warn "crontab not found -- skipping schedule installation (run lintest from your own scheduler)"
    else
        log "installing cron entry (every 5 minutes)"
        # .env is sourced so cron mode gets the same Telegram credentials the
        # systemd unit receives through EnvironmentFile=.
        cron_line="*/5 * * * * set -a; . $INSTALL_DIR/.env; set +a; $VENV_DIR/bin/lintest --config $INSTALL_DIR/config.yaml >> $LOG_DIR/cron.log 2>&1  # lintest"
        ( crontab -u "$SERVICE_USER" -l 2>/dev/null | grep -v 'lintest' || true
          printf '%s\n' "$cron_line" ) | crontab -u "$SERVICE_USER" -
    fi
fi

log "done. Next steps:"
echo "    1. edit $INSTALL_DIR/.env           (Telegram token + chat id)"
echo "    2. edit $INSTALL_DIR/config.yaml    (thresholds, services, hosts)"
echo "    3. one pass now:  $VENV_DIR/bin/lintest --config $INSTALL_DIR/config.yaml --dry-run"
echo "    4. timer status:  systemctl list-timers lintest.timer"
echo "    5. logs:          journalctl -u lintest.service -f   (or $LOG_DIR/lintest.log)"
