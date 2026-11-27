#!/usr/bin/env bash
# ALPHA RADIUS: prepare a Proxmox template VM (Ubuntu Server 24.04, amd64).
#
# Run as root inside the template VM, from a repository checkout, with internet:
#   sudo bash deploy/proxmox/prepare_template.sh build
#       Installs Docker/Nginx, builds the Web/Core/L2TP images, pulls MariaDB and
#       autoheal, installs the runtime files and the first-boot script. Starts
#       NOTHING: no database, no .env, no license, no customer data.
#   (copy the signing key off this VM, delete it here, delete the source checkout)
#   sudo bash /opt/alpha-radius/prepare-template.sh seal
#       Checks the VM is clean and removes per-machine identity (machine-id, SSH
#       host keys). Then: power off, Proxmox Backup, copy the backup file.
#
# At each customer: restore the backup in Proxmox, give the VM a new SMBIOS
# UUID, boot, and run  sudo bash /opt/alpha-radius/first-boot.sh
#
# Independent of install.sh and deploy/local/build_and_start.sh; neither is used
# or changed. Paths can be overridden (INSTALL_DIR, SIGNING_KEY, ALPHA_ETC,
# ALPHA_DMI_UUID_FILE, ALPHA_DBUS_MACHINE_ID, ALPHA_CHECKOUT_SEARCH, ALPHA_BIN_DIR) for testing.
set -Eeuo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_DIR="${INSTALL_DIR:-/opt/alpha-radius}"
SIGNING_KEY="${SIGNING_KEY:-/root/alpha-private/runtime-signing-private.pem}"
ETC="${ALPHA_ETC:-/etc}"
DMI_UUID_FILE="${ALPHA_DMI_UUID_FILE:-/sys/class/dmi/id/product_uuid}"
DBUS_MACHINE_ID="${ALPHA_DBUS_MACHINE_ID:-/var/lib/dbus/machine-id}"
CHECKOUT_SEARCH="${ALPHA_CHECKOUT_SEARCH:-/root /home /opt /srv /tmp}"
TAG="${TAG:-template-$(date -u +%Y%m%d%H%M)}"
DB_IMAGE="mariadb:10.11"
AUTOHEAL_IMAGE="willfarrell/autoheal:latest"

step() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

require_root_and_platform() {
  [[ $EUID -eq 0 ]] || die "Run as root (sudo bash $0 ...)."
  [[ "$(uname -m)" == x86_64 || "$(uname -m)" == amd64 ]] || die "ALPHA RADIUS images are linux/amd64 only."
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    case "${ID:-}" in ubuntu|debian) ;; *) die "Supported: Ubuntu / Debian." ;; esac
  fi
}

# A template must never contain a running system, a database or a .env.
refuse_existing_system() {
  local found=""
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    found+=$(docker ps -a --format '{{.Names}}' | grep -E '^alpha_radius_' || true)
    for volume in alpha-radius_mariadb_data max-radius_mariadb_data; do
      docker volume inspect "$volume" >/dev/null 2>&1 && found+=$'\n'"volume $volume"
    done
  fi
  [[ ! -e "$INSTALL_DIR/.env" ]] || found+=$'\n'"$INSTALL_DIR/.env"
  [[ ! -e "$INSTALL_DIR/.first-boot-done" ]] || found+=$'\n'"$INSTALL_DIR/.first-boot-done"
  for file in instance_id machine_id; do
    [[ ! -e "$INSTALL_DIR/storage/$file" ]] || found+=$'\n'"$INSTALL_DIR/storage/$file"
  done
  if [[ -n "${found//[$'\n']/}" ]]; then
    printf '%s\n' "$found" | sed '/^$/d' >&2
    die "This VM already ran ALPHA RADIUS (items above). Use a fresh Ubuntu VM for the template; nothing was changed."
  fi
}

image_refs() {  # prints the five image references from runtime-release.env
  sed -n 's/^ALPHA_[A-Z0-9]*_IMAGE=\(.*\)$/\1/p' "$INSTALL_DIR/runtime-release.env"
}

cmd_build() {
  require_root_and_platform
  grep -q 'database/radius_message_schema.py' "$SRC/Dockerfile" \
    || die "Run this from an up-to-date repository checkout (git pull)."
  [[ -f "$SRC/deploy/proxmox/first_boot.sh" ]] || die "deploy/proxmox/first_boot.sh is missing."

  rm -f "$INSTALL_DIR/.template-build-complete"
  step "[1/6] Host packages (Docker, Nginx)"
  local nginx_site_existed=0
  [[ ! -f "$ETC/nginx/sites-available/default" ]] || nginx_site_existed=1
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=600 update -q
  apt-get -o DPkg::Lock::Timeout=600 install -y -q ca-certificates curl nginx openssl iproute2
  if ! command -v docker >/dev/null; then
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
  fi
  docker info >/dev/null 2>&1 || die "Docker daemon is not running."
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 plugin is required."
  docker buildx version >/dev/null 2>&1 || die "Docker buildx (BuildKit) is required for the Web image secret."
  refuse_existing_system

  step "[2/6] Runtime signing key"
  if [[ ! -f "$SIGNING_KEY" ]]; then
    install -d -m700 "$(dirname "$SIGNING_KEY")"
    openssl genpkey -algorithm ed25519 -out "$SIGNING_KEY"
    chmod 600 "$SIGNING_KEY"
    echo "Created $SIGNING_KEY. Copy it OFF this VM before 'seal' and reuse it for future builds."
  else
    echo "Using $SIGNING_KEY"
  fi

  step "[3/6] Building images (tag $TAG)"
  local web="gunaid/alpha-radius-web:$TAG" core="gunaid/alpha-radius-core:$TAG" l2tp="gunaid/alpha-radius-l2tp:$TAG"
  DOCKER_BUILDKIT=1 docker build --secret id=runtime_signing_key,src="$SIGNING_KEY" -t "$web" "$SRC"
  docker build -t "$core" "$SRC/docker/freeradius"
  docker build -t "$l2tp" "$SRC/docker/l2tp"
  docker run --rm --network none --entrypoint python "$web" /opt/alpha-protection/verify.py
  docker pull "$DB_IMAGE"
  docker pull "$AUTOHEAL_IMAGE"

  step "[4/6] Runtime files in $INSTALL_DIR"
  install -d "$INSTALL_DIR"
  install -Dm644 "$SRC/docker-compose.production.yml" "$INSTALL_DIR/docker-compose.production.yml"
  install -Dm644 "$SRC/database/schema_mysql.sql" "$INSTALL_DIR/database/schema_mysql.sql"
  install -Dm644 "$SRC/docker/l2tp/options.xl2tpd" "$INSTALL_DIR/docker/l2tp/options.xl2tpd"
  install -Dm644 "$SRC/storage/keys/master_public_key.pem" "$INSTALL_DIR/storage/keys/master_public_key.pem"
  mkdir -p "$INSTALL_DIR/storage/"{backups,uploads,logs,archive,l2tp}
  : > "$INSTALL_DIR/storage/l2tp/chap-secrets"
  : > "$INSTALL_DIR/storage/l2tp/pap-secrets"
  chmod 600 "$INSTALL_DIR/storage/l2tp/"*-secrets
  cat > "$INSTALL_DIR/runtime-release.env" <<EOF
ALPHA_WEB_IMAGE=$web
ALPHA_CORE_IMAGE=$core
ALPHA_L2TP_IMAGE=$l2tp
ALPHA_DB_IMAGE=$DB_IMAGE
ALPHA_AUTOHEAL_IMAGE=$AUTOHEAL_IMAGE
EOF
  chmod 600 "$INSTALL_DIR/runtime-release.env"
  install -m700 "$SRC/deploy/proxmox/first_boot.sh" "$INSTALL_DIR/first-boot.sh"
  install -m700 "$SRC/deploy/proxmox/prepare_template.sh" "$INSTALL_DIR/prepare-template.sh"
  # Interactive static-IP tool for the customer's network (netplan).
  install -Dm755 "$SRC/deploy/ubuntu/alphaip" "${ALPHA_BIN_DIR:-/usr/local/bin}/alphaip"
  printf 'tag=%s\nbuilt=%s\nsource=%s\n' "$TAG" "$(date -u +%FT%TZ)" \
    "$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)" > "$INSTALL_DIR/TEMPLATE_INFO"

  step "[5/6] Nginx (port 80 -> 5090)"
  if [[ $nginx_site_existed -eq 0 ]] || grep -q 'ALPHA RADIUS' "$ETC/nginx/sites-available/default"; then
    install -Dm644 "$SRC/deploy/ubuntu/nginx.conf" "$ETC/nginx/sites-available/default"
    install -d "$ETC/nginx/sites-enabled"
    ln -sf "$ETC/nginx/sites-available/default" "$ETC/nginx/sites-enabled/default"
    nginx -t >/dev/null 2>&1 && (systemctl reload nginx 2>/dev/null || systemctl restart nginx) || echo "WARNING: nginx -t failed; check the site file."
    systemctl enable nginx >/dev/null 2>&1 || true
  else
    echo "Kept the existing custom Nginx site ($ETC/nginx/sites-available/default)."
  fi

  step "[6/6] Regenerate SSH host keys on the customer's first boot"
  install -d "$ETC/systemd/system"
  cat > "$ETC/systemd/system/alpha-ssh-hostkeys.service" <<'EOF'
[Unit]
Description=ALPHA RADIUS: create SSH host keys removed when the template was sealed
ConditionPathExists=!/etc/ssh/ssh_host_ed25519_key
Before=ssh.service ssh.socket sshd.service

[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload 2>/dev/null || true
  systemctl enable alpha-ssh-hostkeys.service >/dev/null 2>&1 || true

  rm -f "$INSTALL_DIR/.template-build-complete"
  date -u +%FT%TZ > "$INSTALL_DIR/.template-build-complete"
  echo
  echo "Template build complete. Images:"
  image_refs | sed 's/^/  /'
  echo
  echo "Next:"
  echo "  1. Copy the signing key OFF this VM and keep it safe: $SIGNING_KEY"
  echo "  2. Delete it here:  shred -u $SIGNING_KEY"
  echo "  3. Delete the source checkout (customers get images only):  rm -rf $SRC"
  echo "  4. sudo bash $INSTALL_DIR/prepare-template.sh seal"
}

cmd_seal() {
  require_root_and_platform
  local yes="${1:-}"
  [[ -f "$INSTALL_DIR/.template-build-complete" && -f "$INSTALL_DIR/runtime-release.env" && -f "$INSTALL_DIR/first-boot.sh" ]] \
    || die "The build stage did not finish. Run 'prepare_template.sh build' again first."
  refuse_existing_system

  step "[1/4] Checking the template is safe to copy"
  local keys
  keys=$(find "$(dirname "$SIGNING_KEY")" -maxdepth 1 -type f -name '*.pem' 2>/dev/null || true)
  [[ ! -f "$SIGNING_KEY" && -z "$keys" ]] || die "Private key still on this VM: $(echo ${keys:-$SIGNING_KEY}). Copy it off, delete it (shred -u), then run seal again."
  # Customers receive images only, never the application sources.
  local checkouts="" dir
  while read -r dir; do
    [[ -z "$dir" ]] || ! grep -qi 'alpharadius' "$dir/config" 2>/dev/null || checkouts+=" $(dirname "$dir")"
  done < <(find $CHECKOUT_SEARCH -maxdepth 4 -type d -name .git 2>/dev/null)
  [[ -z "$checkouts" ]] || die "Source checkout still on this VM:$checkouts. Delete it (rm -rf), then run: sudo bash $INSTALL_DIR/prepare-template.sh seal"
  local missing=""
  while read -r ref; do
    [[ -z "$ref" ]] || docker image inspect "$ref" >/dev/null 2>&1 || missing+=" $ref"
  done < <(image_refs)
  [[ -z "$missing" ]] || die "Images missing (rerun build):$missing"

  if [[ "$yes" != "--yes" ]]; then
    echo "Seal removes this VM's machine-id and SSH host keys (recreated at next boot)."
    read -r -p "Type SEAL to continue: " answer
    [[ "$answer" == SEAL ]] || die "Cancelled; nothing changed."
  fi

  step "[2/4] Recording the template's VM UUID (first boot refuses an unchanged copy)"
  if [[ -r "$DMI_UUID_FILE" ]]; then
    sha256sum < "$DMI_UUID_FILE" | cut -d' ' -f1 > "$INSTALL_DIR/.template-vm-uuid.sha256"
  else
    echo "WARNING: $DMI_UUID_FILE unreadable; first boot cannot detect an unchanged VM UUID."
  fi

  step "[3/4] Removing per-machine identity"
  # Empty (not missing) machine-id: systemd creates a new one on the next boot.
  : > "$ETC/machine-id"
  if [[ -f "$DBUS_MACHINE_ID" && ! -L "$DBUS_MACHINE_ID" ]]; then
    rm -f "$DBUS_MACHINE_ID" && ln -s /etc/machine-id "$DBUS_MACHINE_ID"
  fi
  rm -f "$ETC"/ssh/ssh_host_*
  rm -f /root/.bash_history
  apt-get clean >/dev/null 2>&1 || true
  # Build cache holds intermediate layers (sources before compilation): drop it.
  docker builder prune -af >/dev/null 2>&1 || true
  docker image prune -f >/dev/null 2>&1 || true

  step "[4/4] Done"
  echo "Now: power off this VM (poweroff) and take a Proxmox backup (Backup > Backup now, mode Stop)."
  echo "Do not boot it again before the backup, or seal it again after booting."
}

case "${1:-}" in
  build) cmd_build ;;
  seal) cmd_seal "${2:-}" ;;
  *) echo "Usage: sudo bash $0 build | seal [--yes]" >&2; exit 2 ;;
esac
