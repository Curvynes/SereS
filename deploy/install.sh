#!/usr/bin/env bash
# Installs SereS on Ubuntu / Debian and keeps it running with pm2.
#
#   - installs what is missing: Rust, git, curl, Node.js + npm, pm2
#   - downloads SereS with git, or updates an existing copy with git pull
#   - builds the Rust backend in release mode
#   - installs and sets up a TURN server (coturn) for voice calls
#   - writes ecosystem.config.js (with PUBLIC_URL / WEBAUTHN_RP_ID if given)
#     and starts SereS with pm2
#   - lets pm2 start SereS again after a reboot
#
# Usage (as the user SereS should run as, not as root; asks for sudo):
#   ./deploy/install.sh [--port 2222] [--name SereS]
#        [--public-url https://beta.seres-chat.com] [--rp-id seres-chat.com]
#        [--turn-host 203.0.113.10] [--no-turn]
#        [--dir ~/SereS] [--branch main] [--no-pull] [--no-ipv6] [--no-startup]
#
# Without a SereS checkout around it, the script clones SereS into --dir.
# Run it again at any time to update: it pulls the newest version, installs
# what is new, updates the venv and restarts SereS. Options from the last
# run are kept.

set -euo pipefail

REPO_URL="https://github.com/SereSChat/SereS.git"
BRANCH="main"
DIR=""
NAME=""
PORT=""
TURN=1
TURN_HOST=""
TURN_PORT=3478
TURN_MIN_PORT=49160
TURN_MAX_PORT=49200
PUBLIC_URL=""
RP_ID=""
PULL=1
STARTUP=1
IPV6=1
NODE_MAJOR=22

usage() {
  sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

step() {
  echo
  echo "==> $*"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="${2:-}"; shift 2 ;;
    --name) NAME="${2:-}"; shift 2 ;;
    --public-url) PUBLIC_URL="${2:-}"; shift 2 ;;
    --rp-id) RP_ID="${2:-}"; shift 2 ;;
    --turn-host) TURN_HOST="${2:-}"; shift 2 ;;
    --no-turn) TURN=0; shift ;;
    --dir) DIR="${2:-}"; shift 2 ;;
    --branch) BRANCH="${2:-}"; shift 2 ;;
    --no-pull) PULL=0; shift ;;
    --no-ipv6) IPV6=0; shift ;;
    --no-startup) STARTUP=0; shift ;;
    -h|--help) usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

[[ -z "$PORT" || "$PORT" =~ ^[0-9]+$ ]] || die "--port must be a number"
command -v apt-get >/dev/null || die "only Ubuntu / Debian (apt) are supported"

if [[ $EUID -eq 0 ]]; then
  SUDO=""
  echo "Note: running as root, so SereS and pm2 run as root too."
  echo "      Better: create a user (adduser seres) and run the script as that user."
else
  command -v sudo >/dev/null || die "sudo is missing; run as root or install sudo"
  SUDO="sudo"
fi
RUN_USER="$(id -un)"
RUN_HOME="$HOME"

# ---------------------------------------------------------------- packages

step "Installing system packages (git, curl)"
$SUDO apt-get update -qq
$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  git curl ca-certificates gnupg build-essential pkg-config libssl-dev >/dev/null

node_ok() {
  command -v node >/dev/null && command -v npm >/dev/null || return 1
  local major
  major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  [[ "$major" -ge 18 ]]
}

if node_ok; then
  step "Node.js $(node -v) and npm $(npm -v) are already installed"
else
  step "Installing Node.js $NODE_MAJOR with npm (NodeSource)"
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | ${SUDO:+$SUDO -E} bash - >/dev/null
  $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nodejs >/dev/null
  node_ok || die "Node.js could not be installed"
  echo "    Node.js $(node -v), npm $(npm -v)"
fi

if command -v pm2 >/dev/null; then
  step "pm2 $(pm2 -v 2>/dev/null | tail -n 1) is already installed"
else
  step "Installing pm2"
  $SUDO npm install -g pm2 >/dev/null
  command -v pm2 >/dev/null || die "pm2 could not be installed"
fi

if [[ ! -x "$RUN_HOME/.cargo/bin/rustup" ]]; then
  step "Installing Rust stable with rustup"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
fi
[[ -f "$RUN_HOME/.cargo/env" ]] && source "$RUN_HOME/.cargo/env"
"$RUN_HOME/.cargo/bin/rustup" toolchain install stable --profile minimal --no-self-update >/dev/null
"$RUN_HOME/.cargo/bin/rustup" default stable >/dev/null
export PATH="$RUN_HOME/.cargo/bin:$PATH"
command -v cargo >/dev/null || die "Rust could not be installed"

# ------------------------------------------------------------------- SereS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "$DIR" && -f "$SCRIPT_DIR/../src/backend-rs/Cargo.toml" ]]; then
  DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
  step "Using SereS in $DIR"
else
  DIR="${DIR:-$RUN_HOME/SereS}"
  if [[ -f "$DIR/src/backend-rs/Cargo.toml" ]]; then
    step "Using SereS in $DIR"
  else
    [[ -e "$DIR" && -n "$(ls -A "$DIR" 2>/dev/null)" ]] && die "$DIR exists but is not SereS"
    step "Downloading SereS ($BRANCH) to $DIR"
    git clone --branch "$BRANCH" "$REPO_URL" "$DIR"
  fi
fi

if [[ $PULL -eq 1 && -d "$DIR/.git" ]]; then
  step "Updating SereS with git pull"
  # Changes made by hand (e.g. mail settings in src/backend/.env) are put
  # aside for the pull and put back afterwards.
  git -C "$DIR" pull --ff-only --autostash ||
    echo "    git pull failed, keeping the current version (see: git -C $DIR status)."
fi
BACKEND="$DIR/src/backend"
PUBLIC_DIR="$DIR/src/public"
BIN="$DIR/src/backend-rs/target/release/seres-backend"

step "Building the Rust backend"
cargo build --release --locked --manifest-path "$DIR/src/backend-rs/Cargo.toml"
[[ -x "$BIN" ]] || die "Rust backend build did not produce $BIN"

# Settings from an earlier run stay when the options are left out. They are
# kept in ecosystem.config.js instead of src/backend/.env, because .env is part
# of the repository and a changed .env would block "git pull".
previous() {
  [[ -f "$DIR/ecosystem.config.js" ]] || return 0
  node -e 'try { const app=require(process.argv[1]).apps?.[0]; const key=process.argv[2]; const v=app?.env?.[key]; if (v !== undefined) process.stdout.write(String(v)); else if (key === "PORT") { const m=String(app?.args || "").match(/-b 127\.0\.0\.1:(\d+)/); if (m) process.stdout.write(m[1]); } } catch {}' \
    "$DIR/ecosystem.config.js" "$1"
}
previous_name() {
  [[ -f "$DIR/ecosystem.config.js" ]] || return 0
  node -e 'try { const c=require(process.argv[1]); process.stdout.write(String(c.apps?.[0]?.name || "")); } catch {}' \
    "$DIR/ecosystem.config.js"
}
NAME="${NAME:-$(previous_name)}"
NAME="${NAME:-SereS}"
PUBLIC_URL="${PUBLIC_URL:-$(previous PUBLIC_URL)}"
RP_ID="${RP_ID:-$(previous WEBAUTHN_RP_ID)}"
PORT="${PORT:-$(previous PORT)}"
PORT="${PORT:-2222}"

# ------------------------------------------------------------------- TURN

# Calls go directly between the browsers. When that is not possible (some
# mobile networks, company Wi-Fi), the audio is relayed by this TURN server.
# It doesn't go through the Cloudflare tunnel, so its ports must be open.
TURN_CONF=/etc/turnserver.conf
TURN_MARK="# Written by SereS deploy/install.sh"
if [[ $TURN -eq 1 ]]; then
  if command -v turnserver >/dev/null; then
    step "coturn is already installed"
  else
    step "Installing coturn (TURN server for calls)"
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq coturn >/dev/null
  fi

  if [[ -z "$TURN_HOST" ]]; then
    TURN_HOST="$(previous TURN_URLS | sed -n 's/^turn:\([^:?,]*\).*/\1/p')"
  fi
  if [[ -z "$TURN_HOST" ]]; then
    TURN_HOST="$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
  fi
  [[ "$TURN_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || die "could not find the public address; use --turn-host"

  TURN_SECRET=""
  if $SUDO test -f "$TURN_CONF" && $SUDO grep -q "^$TURN_MARK" "$TURN_CONF"; then
    TURN_SECRET="$($SUDO sed -n 's/^static-auth-secret=//p' "$TURN_CONF" | head -n 1)"
  elif $SUDO test -f "$TURN_CONF"; then
    $SUDO cp -n "$TURN_CONF" "$TURN_CONF.before-seres"
  fi
  TURN_SECRET="${TURN_SECRET:-$(node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))')}"
  [[ "$TURN_SECRET" =~ ^[0-9a-f]+$ ]] || die "unexpected TURN secret in $TURN_CONF"

  step "Writing $TURN_CONF (TURN on $TURN_HOST:$TURN_PORT)"
  $SUDO tee "$TURN_CONF" >/dev/null <<TURNCONF
$TURN_MARK. Run the script again instead of changing it.
listening-port=$TURN_PORT
min-port=$TURN_MIN_PORT
max-port=$TURN_MAX_PORT
realm=$TURN_HOST
fingerprint
use-auth-secret
static-auth-secret=$TURN_SECRET
no-cli
no-tls
no-dtls
no-multicast-peers
stale-nonce=600
user-quota=12
total-quota=1200
simple-log
syslog
# Only relay to the internet, never into this server or private networks.
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.0.0.0-192.0.0.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=198.18.0.0-198.19.255.255
denied-peer-ip=::1
denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
TURNCONF
  $SUDO chmod 640 "$TURN_CONF"
  $SUDO chown root:turnserver "$TURN_CONF" 2>/dev/null || true
  # Older Debian packages only start coturn with this switch.
  if [[ -f /etc/default/coturn ]]; then
    $SUDO sed -i 's/^#\?TURNSERVER_ENABLED=.*/TURNSERVER_ENABLED=1/' /etc/default/coturn
  fi
  if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then
    $SUDO systemctl enable coturn >/dev/null 2>&1 || true
    $SUDO systemctl restart coturn || echo "    coturn did not start, see: sudo journalctl -u coturn"
  else
    echo "    No systemd here: start coturn yourself (turnserver -c $TURN_CONF)."
  fi

fi

# ------------------------------------------------------------------- pm2

step "Writing $DIR/ecosystem.config.js"
export SERES_PM2_NAME="$NAME" SERES_PM2_BIN="$BIN" SERES_PM2_CWD="$BACKEND"
export SERES_PM2_PORT="$PORT" SERES_PM2_PUBLIC_DIR="$PUBLIC_DIR" SERES_PM2_DATA_DIR="$BACKEND"
export SERES_PM2_PUBLIC_URL="$PUBLIC_URL" SERES_PM2_RP_ID="$RP_ID"
IPV6_HOST=""
if [[ $IPV6 -eq 1 ]] && node -e 'const net=require("net");const s=net.createServer();s.once("error",()=>process.exit(1));s.listen({host:"::1",port:0},()=>s.close());' 2>/dev/null; then
  IPV6_HOST="::1"
fi
export SERES_PM2_IPV6_HOST="$IPV6_HOST"
export SERES_PM2_TURN_HOST="$TURN_HOST" SERES_PM2_TURN_PORT="$TURN_PORT"
export SERES_PM2_TURN_SECRET="${TURN_SECRET:-}"
export SERES_PM2_TURN_ENABLED="$TURN"
export SERES_PM2_CONFIG="$DIR/ecosystem.config.js"
node <<'NODE'
const fs = require('fs');
const env = {
  HOST: '127.0.0.1',
  PORT: process.env.SERES_PM2_PORT,
  SERES_PUBLIC_DIR: process.env.SERES_PM2_PUBLIC_DIR,
  SERES_DATA_DIR: process.env.SERES_PM2_DATA_DIR,
};
if (process.env.SERES_PM2_PUBLIC_URL) env.PUBLIC_URL = process.env.SERES_PM2_PUBLIC_URL;
if (process.env.SERES_PM2_RP_ID) env.WEBAUTHN_RP_ID = process.env.SERES_PM2_RP_ID;
if (process.env.SERES_PM2_IPV6_HOST) env.SERES_EXTRA_HOST = process.env.SERES_PM2_IPV6_HOST;
if (process.env.SERES_PM2_TURN_ENABLED === '1') {
  env.TURN_URLS = `turn:${process.env.SERES_PM2_TURN_HOST}:${process.env.SERES_PM2_TURN_PORT}?transport=udp,turn:${process.env.SERES_PM2_TURN_HOST}:${process.env.SERES_PM2_TURN_PORT}?transport=tcp`;
  env.TURN_SECRET = process.env.SERES_PM2_TURN_SECRET;
}
const config = { apps: [{ name: process.env.SERES_PM2_NAME, cwd: process.env.SERES_PM2_CWD,
  script: process.env.SERES_PM2_BIN, args: '', interpreter: 'none', autorestart: true, env }] };
fs.writeFileSync(process.env.SERES_PM2_CONFIG,
  `// Written by deploy/install.sh. Start with: pm2 start ecosystem.config.js\nmodule.exports = ${JSON.stringify(config, null, 2)};\n`,
  { mode: 0o600 });
NODE
# It contains the TURN secret.
chmod 600 "$DIR/ecosystem.config.js"

step "Starting SereS with pm2"
pm2 delete "$NAME" >/dev/null 2>&1 || true
pm2 start "$DIR/ecosystem.config.js" >/dev/null
pm2 save >/dev/null

if [[ $STARTUP -eq 1 ]]; then
  step "Starting pm2 automatically after a reboot"
  $SUDO env PATH="$PATH" "$(command -v pm2)" startup systemd -u "$RUN_USER" --hp "$RUN_HOME" >/dev/null
  pm2 save >/dev/null
fi

step "Checking http://127.0.0.1:$PORT/"
status=""
for _ in $(seq 1 20); do
  status="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/" || true)"
  [[ "$status" == "200" ]] && break
  sleep 1
done

echo
if [[ "$status" == "200" ]]; then
  echo "SereS is running on http://127.0.0.1:$PORT/ (pm2 name: $NAME)."
else
  echo "SereS does not answer yet (HTTP ${status:-none}). Look at the log:"
  echo "    pm2 logs $NAME --lines 50"
fi
cat <<EOF

Useful commands:
    pm2 status                 is SereS running?
    pm2 logs $NAME             show the log
    pm2 restart $NAME          restart, e.g. after changing .env

Update SereS later (pulls the newest version and restarts):
    $DIR/deploy/install.sh

SereS only listens on this server. Point your Cloudflare tunnel or
reverse proxy (nginx, Caddy) to http://localhost:$PORT.
EOF
if [[ $TURN -eq 1 ]]; then
  cat <<EOF

Voice calls: open these ports in the firewall of your hoster (e.g. netcup
SCP -> Firewall) and on the server, if it has one (ufw):
    TCP + UDP $TURN_PORT
    UDP $TURN_MIN_PORT-$TURN_MAX_PORT
Calls still work without them for most people, just not in every network.
EOF
fi
