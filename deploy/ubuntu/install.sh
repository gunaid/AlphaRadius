#!/usr/bin/env bash
# Compatibility entrypoint: use the protected runtime installer, never a source build.
set -Eeuo pipefail
installer=$(mktemp)
trap 'rm -f -- "$installer"' EXIT
curl --fail --location --retry 3 --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/gunaid/AlphaRadius/main/install.sh -o "$installer"
bash "$installer" "$@"
