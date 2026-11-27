#!/usr/bin/env bash
# ALPHA RADIUS: first start of a VM restored from the Proxmox template.
# No internet needed: every image is already inside the VM.
#
#   sudo bash /opt/alpha-radius/first-boot.sh [--admin-port 43333] [--timezone Asia/Aden] [--yes]
#
# Creates this customer's own secrets (database passwords, RADIUS health secret)
# and installation ID, then starts the services from the local images. It runs
# once: an installed system is never touched again (use the normal update path).
# Paths can be overridden (INSTALL_DIR, ALPHA_ETC, ALPHA_DMI_UUID_FILE) for testing.
set -Eeuo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/alpha-radius}"
ETC="${ALPHA_ETC:-/etc}"
DMI_UUID_FILE="${ALPHA_DMI_UUID_FILE:-/sys/class/dmi/id/product_uuid}"
ADMIN_PORT=""
TIMEZONE="Asia/Aden"
YES=""

step() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin-port) ADMIN_PORT="${2:-}"; shift 2 ;;
    --timezone) TIMEZONE="${2:-}"; shift 2 ;;
    --yes) YES=1; shift ;;
    *) echo "Usage: sudo bash $0 [--admin-port PORT] [--timezone Area/City] [--yes]" >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Run as root (sudo bash $0)."
if [[ -n "$ADMIN_PORT" ]]; then
  [[ "$ADMIN_PORT" =~ ^[0-9]{2,5}$ ]] && (( ADMIN_PORT >= 1024 && ADMIN_PORT <= 65535 )) \
    || die "--admin-port must be a number from 1024 to 65535."
  case "$ADMIN_PORT" in 1701|1812|1813|3307|5090|37990) die "--admin-port $ADMIN_PORT is already used by the system." ;; esac
fi
[[ "$TIMEZONE" =~ ^[A-Za-z_]+(/[A-Za-z0-9_+-]+)*$ ]] || die "Invalid --timezone."

cd "$INSTALL_DIR" 2>/dev/null || die "$INSTALL_DIR not found: this VM was not made from the template."
[[ -f runtime-release.env && -f docker-compose.production.yml ]] || die "Template files missing in $INSTALL_DIR."
[[ ! -e .first-boot-done ]] || die "First boot already done on $(cat .first-boot-done). Nothing changed."
[[ ! -e .env ]] || die "$INSTALL_DIR/.env exists: this VM already has a configuration. Nothing changed."

step "[1/6] Checks"
docker info >/dev/null 2>&1 || die "Docker daemon is not running (systemctl start docker)."
existing=$(docker ps -a --format '{{.Names}}' | grep -E '^alpha_radius_' || true)
[[ -z "$existing" ]] || die "Containers already exist: $existing"
! docker volume inspect alpha-radius_mariadb_data >/dev/null 2>&1 || die "A database volume already exists (alpha-radius_mariadb_data)."
for file in instance_id machine_id; do
  [[ ! -e "storage/$file" ]] || die "storage/$file exists: copied from another installation. Remove the VM and restore the template again."
done
# A restored copy that keeps the template's VM UUID would share the hardware
# fingerprint (license binding) with every other customer made from it.
if [[ -f .template-vm-uuid.sha256 ]]; then
  if [[ -r "$DMI_UUID_FILE" ]]; then
    if [[ "$(sha256sum < "$DMI_UUID_FILE" | cut -d' ' -f1)" == "$(cat .template-vm-uuid.sha256)" ]]; then
      die "This VM still has the template's UUID. In Proxmox: VM > Options > SMBIOS settings (type1) > generate a new UUID, shut down, start, and run again."
    fi
  else
    echo "WARNING: cannot read $DMI_UUID_FILE; make sure this VM has its own SMBIOS UUID."
  fi
fi
missing=""
while read -r ref; do
  [[ -z "$ref" ]] || docker image inspect "$ref" >/dev/null 2>&1 || missing+=" $ref"
done < <(sed -n 's/^ALPHA_[A-Z0-9]*_IMAGE=\(.*\)$/\1/p' runtime-release.env)
[[ -z "$missing" ]] || die "Images missing from this VM:$missing"
if command -v timedatectl >/dev/null && [[ $(timedatectl show -p NTPSynchronized --value 2>/dev/null) != yes ]]; then
  echo "WARNING: the clock is not synchronized. License activation needs the correct date and time:"
  date
fi

if [[ -z "$YES" ]]; then
  echo "This creates new secrets and starts ALPHA RADIUS on this VM${ADMIN_PORT:+ (admin panel on port $ADMIN_PORT)}."
  read -r -p "Type START to continue: " answer
  [[ "$answer" == START ]] || die "Cancelled; nothing changed."
fi

step "[2/6] Machine identity"
ROOT_FS="$(dirname "$ETC")"   # "/" normally
if [[ ! -s "$ETC/machine-id" ]] && command -v systemd-machine-id-setup >/dev/null; then
  systemd-machine-id-setup --root="$ROOT_FS" >/dev/null
fi
ls "$ETC"/ssh/ssh_host_*_key >/dev/null 2>&1 || ssh-keygen -A -f "$ROOT_FS" >/dev/null 2>&1 || true

step "[3/6] This installation's secrets ($INSTALL_DIR/.env)"
umask 077
{
  printf 'RADIUS_HEALTH_SECRET=%s\n' "$(openssl rand -hex 16)"
  printf 'SYSTEM_TIMEZONE=%s\n' "$TIMEZONE"
  printf 'ALPHA_DB_PASSWORD=%s\n' "$(openssl rand -hex 24)"
  printf 'ALPHA_DB_ROOT_PASSWORD=%s\n' "$(openssl rand -hex 24)"
  [[ -z "$ADMIN_PORT" ]] || printf 'ALPHA_ADMIN_PORT=%s\n' "$ADMIN_PORT"
} > .env.new
mv .env.new .env
chmod 600 .env
timedatectl set-timezone "$TIMEZONE" 2>/dev/null || true

step "[4/6] Host networking"
install -d "$ETC/sysctl.d"
cat > "$ETC/sysctl.d/99-alpharadius.conf" <<'EOF'
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
[[ -e /dev/ppp ]] || modprobe ppp_generic 2>/dev/null || true
if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
  for port in 80/tcp 5090/tcp ${ADMIN_PORT:+$ADMIN_PORT/tcp} 1812/udp 1813/udp 37990/udp 1701/udp; do ufw allow "$port" >/dev/null; done
fi

step "[5/6] Starting services from local images (no download)"
compose=(docker compose --project-directory "$INSTALL_DIR" --env-file "$INSTALL_DIR/.env"
         --env-file "$INSTALL_DIR/runtime-release.env" -f "$INSTALL_DIR/docker-compose.production.yml")
"${compose[@]}" config --quiet
"${compose[@]}" up -d --pull never --wait --wait-timeout 240 mariadb
"${compose[@]}" up -d --pull never --wait --wait-timeout 300 wisp-web
"${compose[@]}" up -d --pull never --wait --wait-timeout 300
ip route replace 192.168.44.0/24 via 172.18.0.10 2>/dev/null || true
docker exec alpha_radius_web python /opt/alpha-protection/verify.py

step "[6/6] Done"
date -u +%FT%TZ > .first-boot-done
"${compose[@]}" ps
ip_address=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
if [[ -n "$ADMIN_PORT" ]]; then
  echo "Admin panel:       http://${ip_address:-<server-ip>}:$ADMIN_PORT"
  echo "Subscriber portal: http://${ip_address:-<server-ip>}"
else
  echo "Admin panel:       http://${ip_address:-<server-ip>}:5090"
fi
echo "Next: log in, change the initial administrator password, and activate the license."
echo "Secrets are in $INSTALL_DIR/.env (root only). Keep a copy with this customer's records."
