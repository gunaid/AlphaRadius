#!/usr/bin/env bash
# Build ALPHA RADIUS images on this machine and start the production stack.
#
# Run as root from the repository checkout:
#   sudo bash deploy/local/build_and_start.sh
#
# Environment overrides:
#   TAG          image tag to build            (default: local-YYYYmmddHHMM)
#   INSTALL_DIR  runtime directory             (default: /opt/alpha-radius)
#   SIGNING_KEY  runtime signing private key   (default: /root/alpha-private/runtime-signing-private.pem,
#                                               generated once if missing; keep it, never commit it)
#
# Mirrors install.sh, but images are built locally instead of pulled from a
# registry. Existing storage, .env and database volumes are never replaced.
set -Eeuo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TAG="${TAG:-local-$(date -u +%Y%m%d%H%M)}"
INSTALL_DIR="${INSTALL_DIR:-/opt/alpha-radius}"
SIGNING_KEY="${SIGNING_KEY:-/root/alpha-private/runtime-signing-private.pem}"
WEB_IMAGE="gunaid/alpha-radius-web:$TAG"
CORE_IMAGE="gunaid/alpha-radius-core:$TAG"
L2TP_IMAGE="gunaid/alpha-radius-l2tp:$TAG"

step() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

step "[1/7] Checking prerequisites"
[[ $EUID -eq 0 ]] || die "Run as root (sudo bash $0)."
command -v docker >/dev/null || die "Docker is not installed."
docker info >/dev/null 2>&1 || die "Docker daemon is not running."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 plugin is required."
docker buildx version >/dev/null 2>&1 || die "Docker buildx (BuildKit) is required for the Web image secret."
command -v openssl >/dev/null || die "openssl is required to create the signing key."
grep -q 'database/radius_message_schema.py' "$SRC/Dockerfile" \
  || die "This checkout lacks the Dockerfile fix (commit 03ed516). Update the repository first."

# Ports used by the stack; another running stack (for example the old MAX
# RADIUS containers) would make startup fail half-way.
busy=$(docker ps --format '{{.Names}} {{.Ports}}' | grep -E ':(5090|1812|1813|1701|37990)->' | grep -v '^alpha_radius_' || true)
if [[ -n "$busy" ]]; then
  printf '%s\n' "$busy"
  die "Containers above already use the system ports. Stop them first (data volumes are not touched by stopping)."
fi
for volume in max-radius_mariadb_data max_radius_mariadb_data; do
  if docker volume inspect "$volume" >/dev/null 2>&1; then
    echo "NOTE: old database volume '$volume' exists. This script starts a NEW database"
    echo "      (alpha-radius_mariadb_data) and does not migrate or delete the old one."
  fi
done

step "[2/7] Runtime signing key"
if [[ ! -f "$SIGNING_KEY" ]]; then
  install -d -m700 "$(dirname "$SIGNING_KEY")"
  openssl genpkey -algorithm ed25519 -out "$SIGNING_KEY"
  chmod 600 "$SIGNING_KEY"
  echo "Created $SIGNING_KEY (keep it; reuse it for every future build)."
else
  echo "Using existing $SIGNING_KEY"
fi

step "[3/7] Building images (tag $TAG)"
DOCKER_BUILDKIT=1 docker build --secret id=runtime_signing_key,src="$SIGNING_KEY" -t "$WEB_IMAGE" "$SRC"
docker build -t "$CORE_IMAGE" "$SRC/docker/freeradius"
docker build -t "$L2TP_IMAGE" "$SRC/docker/l2tp"
# The same integrity check the container runs at start, before any switch.
docker run --rm --network none --entrypoint python "$WEB_IMAGE" /opt/alpha-protection/verify.py

step "[4/7] Installing runtime configuration into $INSTALL_DIR"
install -d "$INSTALL_DIR"
backup="$INSTALL_DIR/.install-backups/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$backup"
for file in docker-compose.production.yml runtime-release.env .env; do
  [[ ! -f "$INSTALL_DIR/$file" ]] || cp -p -- "$INSTALL_DIR/$file" "$backup/"
done
install -Dm644 "$SRC/docker-compose.production.yml" "$INSTALL_DIR/docker-compose.production.yml"
install -Dm644 "$SRC/database/schema_mysql.sql" "$INSTALL_DIR/database/schema_mysql.sql"
install -Dm644 "$SRC/docker/l2tp/options.xl2tpd" "$INSTALL_DIR/docker/l2tp/options.xl2tpd"
if [[ ! -f "$INSTALL_DIR/storage/keys/master_public_key.pem" ]]; then
  install -Dm644 "$SRC/storage/keys/master_public_key.pem" "$INSTALL_DIR/storage/keys/master_public_key.pem"
fi
mkdir -p "$INSTALL_DIR/storage/"{backups,uploads,logs,archive,l2tp}
touch "$INSTALL_DIR/storage/l2tp/chap-secrets" "$INSTALL_DIR/storage/l2tp/pap-secrets"
chmod 600 "$INSTALL_DIR/storage/l2tp/"*-secrets
cat > "$INSTALL_DIR/runtime-release.env" <<EOF
ALPHA_WEB_IMAGE=$WEB_IMAGE
ALPHA_CORE_IMAGE=$CORE_IMAGE
ALPHA_L2TP_IMAGE=$L2TP_IMAGE
ALPHA_DB_IMAGE=mariadb:10.11
ALPHA_AUTOHEAL_IMAGE=willfarrell/autoheal:latest
EOF
chmod 600 "$INSTALL_DIR/runtime-release.env"
if [[ ! -f "$INSTALL_DIR/.env" ]]; then
  # A random health-check secret instead of the compose default.
  printf 'RADIUS_HEALTH_SECRET=%s\nSYSTEM_TIMEZONE=%s\n' "$(openssl rand -hex 16)" "${SYSTEM_TIMEZONE:-Asia/Aden}" > "$INSTALL_DIR/.env"
  chmod 600 "$INSTALL_DIR/.env"
fi

step "[5/7] Host networking"
cat > /etc/sysctl.d/99-alpharadius.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.netdev_max_backlog = 10000
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
EOF
sysctl --system -q 2>/dev/null || true
if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
  for port in 80/tcp 5090/tcp 1812/udp 1813/udp 37990/udp 1701/udp; do ufw allow "$port" >/dev/null; done
fi

compose=(docker compose --project-directory "$INSTALL_DIR" --env-file "$INSTALL_DIR/.env"
         --env-file "$INSTALL_DIR/runtime-release.env" -f "$INSTALL_DIR/docker-compose.production.yml")
"${compose[@]}" config --quiet

step "[6/7] Starting: database, then Web (creates schema and fn_rmsg), then Core and the rest"
"${compose[@]}" up -d --wait --wait-timeout 240 mariadb
"${compose[@]}" up -d --wait --wait-timeout 300 wisp-web
"${compose[@]}" up -d --wait --wait-timeout 300

step "[7/7] Status"
"${compose[@]}" ps
echo
echo "Images: $WEB_IMAGE  $CORE_IMAGE  $L2TP_IMAGE"
echo "Panel:  http://<this-machine-ip>:5090"
echo "Config backups of the previous run (if any): $backup"
