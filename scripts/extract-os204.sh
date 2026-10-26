#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
NIXPKGS=github:NixOS/nixpkgs/eaad089433ca2bb662274377d33df3d0e51ef28b

usage() {
  cat <<'EOF'
Usage: scripts/extract-os204.sh --images IMAGES_DIR [--help]
   or: OS204_IMAGES=IMAGES_DIR scripts/extract-os204.sh [--help]

Extract official OS2.0.4 payloads and pinned upstream runtime firmware into
assets/. The input directory is read-only. Temporary unpacking is removed
automatically; regeneration replaces only generated assets and MANIFEST.tsv.

Uses the target flake's pinned Nixpkgs revision for linux-firmware,
wireless-regdb, extraction tools, and AudioReach build tools.
EOF
  printf 'Set --images or OS204_IMAGES to the official OS2.0.4 images directory.\n'
}

images=${OS204_IMAGES:-}
while (($#)); do
  case "$1" in
    --images) (($# >= 2)) || { usage >&2; exit 2; }; images=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$images" ]] || { printf 'Set --images or OS204_IMAGES to the official OS2.0.4 images directory.\n' >&2; usage >&2; exit 2; }

[[ -d "$images" ]] || { printf 'Images directory not found: %s\n' "$images" >&2; exit 2; }
for image in super.img vendor_boot.img dtbo.img NON-HLOS.bin BTFM.bin; do
  [[ -f "$images/$image" ]] || { printf 'Required official image missing: %s/%s\n' "$images" "$image" >&2; exit 2; }
done

linux_firmware=$(nix build --no-link --print-out-paths "$NIXPKGS#linux-firmware")
wireless_regdb=$(nix build --no-link --print-out-paths "$NIXPKGS#wireless-regdb")
exec nix shell "$NIXPKGS#android-tools" "$NIXPKGS#erofs-utils" "$NIXPKGS#mtools" \
  "$NIXPKGS#zstd" "$NIXPKGS#git" "$NIXPKGS#m4" "$NIXPKGS#alsa-utils" \
  "$NIXPKGS#python3" "$NIXPKGS#coreutils" "$NIXPKGS#gnugrep" "$NIXPKGS#gawk" \
  -c python3 "$SCRIPT_DIR/extract-os204.py" --images "$images" --repo "$REPO_ROOT" \
  --linux-firmware "$linux_firmware" --wireless-regdb "$wireless_regdb"
