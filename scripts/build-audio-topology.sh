#!/usr/bin/env sh
# SPDX-License-Identifier: BSD-3-Clause
# Build AudioReach firmware only from the pinned open-source source revision.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
src=${AUDIOREACH_TOPOLOGY_DIR:?set AUDIOREACH_TOPOLOGY_DIR to the pinned AudioReach checkout}
expected_commit=2af1f1ebb8d4fd03b5f53891467ddde2e208a8a0
board=$root/scripts/audio-topology/liuqin-speakers.m4
output=${OUTPUT:?set OUTPUT to an isolated output path}

die() { printf 'build-audio-topology: %s\n' "$*" >&2; exit 1; }

[ -f "$board" ] || die "board topology missing: $board"
git -C "$src" rev-parse --git-dir >/dev/null 2>&1 || die "not a git checkout: $src"
[ "$(git -C "$src" rev-parse HEAD)" = "$expected_commit" ] || die 'AudioReach source commit mismatch'
[ -z "$(git -C "$src" status --porcelain --untracked-files=no)" ] || die 'AudioReach source is dirty'
command -v m4 >/dev/null 2>&1 || die 'm4 is unavailable'
command -v alsatplg >/dev/null 2>&1 || die 'alsatplg is unavailable'

tmp=$(mktemp -d "${TMPDIR:-/tmp}/liuqin-audio.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

m4 -I "$src" "$board" >"$tmp/control.conf"
control_mid='                AR_TKN_U32_MODULE_ID "0x0700117C"'
legacy_mid='                AR_TKN_U32_MODULE_ID "0x0700100E"'
[ "$(grep -Fxc "$control_mid" "$tmp/control.conf")" -eq 1 ] || die 'unexpected Audio-IF sink MID'
awk -v old="$control_mid" -v new="$legacy_mid" '
	$0 == old { print new; changed++; next }
	{ print }
	END { if (changed != 1) exit 42 }
' "$tmp/control.conf" >"$tmp/candidate.conf" || die 'failed to select legacy TDM sink'

alsatplg -c "$tmp/candidate.conf" -o "$tmp/candidate.bin"
alsatplg -d "$tmp/candidate.bin" -o "$tmp/decoded.conf"
for value in "formats 'S24_LE'" 'channels_min 4' 'channels_max 4' 'token1 56' \
	'token264 15' 'token265 4' 'token266 32' 'token273 48000'; do
	grep -Fq "$value" "$tmp/decoded.conf" || die "decoded topology lacks $value"
done
awk '$1 == "token200" && $2 == 117444622 { count++ } END { exit count == 1 ? 0 : 1 }' \
	"$tmp/decoded.conf" || die 'decoded topology has the wrong playback endpoint MID'
grep -Fq "'TERTIARY_TDM_RX_0 Audio Mixer, MultiMedia1, stream0.logger1'" \
	"$tmp/decoded.conf" || die 'playback route is missing'
awk '$1 == "token200" && $2 == 117444644 { count++ } END { exit count == 1 ? 0 : 1 }' \
	"$tmp/decoded.conf" || die 'capture topology lacks codec-DMA capture MID'
for value in "stream_name 'MultiMedia2 Capture'" "stream_name 'TX_CODEC_DMA_TX_3 Capture'" \
	"'device120.codec_dma_tx1, , TX_CODEC_DMA_TX_3 Capture'" \
	"'MultiMedia2 Mixer, TX_CODEC_DMA_TX_3, device120.logger1'"; do
	grep -Fq "$value" "$tmp/decoded.conf" || die "decoded topology lacks capture element: $value"
done
mkdir -p "$(dirname -- "$output")"
install -m 0644 "$tmp/candidate.bin" "$output"
