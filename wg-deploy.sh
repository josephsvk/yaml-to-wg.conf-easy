#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# WireGuard deploy helper: copy conf -> /etc/wireguard, optionally apply patches,
# then enable + restart wg-quick@<ifname>
#
# Usage:
#   sudo ./wg-deploy.sh            # deploy all entries below
#   sudo ./wg-deploy.sh wg3        # deploy only wg3 (matches IFACE)
#
# Add new tunnels by appending one block into CONFIGS array.
# Add patches by placing files into: ./patches/<ifname>/*.patch
# Patches are applied onto /etc/wireguard/<ifname>.conf before restart.
# ==============================================================================

# --- SIMPLE "DATABASE" --------------------------------------------------------
# Format per entry: IFACE|SRC_CONF_ABS_PATH
CONFIGS=(
  "wg3|/home/joseph/VPS/wg/out/wg3/wg3.conf"
  "wg2|/home/joseph/VPS/wg/out/wg2/wg2.conf"
  # "wg1|/home/joseph/VPS/wg/out/wg1/wg1.conf"
)

# Where patches live (relative to this script)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PATCH_ROOT="${SCRIPT_DIR}/patches"

# /etc destination
WG_ETC_DIR="/etc/wireguard"

# --- INTERNALS ----------------------------------------------------------------
die() { echo "ERROR: $*" >&2; exit 1; }

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "run as root (sudo)"
}

ensure_tools() {
  command -v systemctl >/dev/null || die "systemctl not found"
  command -v wg >/dev/null || die "wg not found"
  command -v wg-quick >/dev/null || die "wg-quick not found"
  command -v patch >/dev/null || die "patch not found"
}

deploy_one() {
  local iface="$1"
  local src="$2"
  local dst="${WG_ETC_DIR}/${iface}.conf"
  local patch_dir="${PATCH_ROOT}/${iface}"

  [[ -f "${src}" ]] || die "missing source conf: ${src}"

  install -d -m 700 "${WG_ETC_DIR}"
  cp -f "${src}" "${dst}"
  chmod 600 "${dst}"

  # Apply patches if present
  if [[ -d "${patch_dir}" ]]; then
    shopt -s nullglob
    local patches=( "${patch_dir}"/*.patch )
    shopt -u nullglob
    if (( ${#patches[@]} > 0 )); then
      for p in "${patches[@]}"; do
        # Apply patch onto the destination conf
        patch -N -r - "${dst}" < "${p}" >/dev/null
      done
    fi
  fi

  # Enable + restart
  systemctl enable "wg-quick@${iface}" >/dev/null || true
  systemctl restart "wg-quick@${iface}"

  # Quick sanity
  wg show "${iface}" >/dev/null
  echo "OK: ${iface} deployed -> ${dst} and restarted"
}

main() {
  need_root
  ensure_tools

  local filter="${1:-}"

  # Deploy selected/all
  local any=0
  for entry in "${CONFIGS[@]}"; do
    IFS='|' read -r iface src <<<"${entry}"
    if [[ -n "${filter}" && "${iface}" != "${filter}" ]]; then
      continue
    fi
    any=1
    deploy_one "${iface}" "${src}"
  done

  (( any == 1 )) || die "no matching config for '${filter}'"
}

main "$@"
