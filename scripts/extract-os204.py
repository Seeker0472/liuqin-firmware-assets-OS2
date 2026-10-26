#!/usr/bin/env python3
"""Extract the narrow OS2.0.4 binary payload set from official partition images."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import atexit
import os
import sys

SOURCE_IMAGES = {
    "super.img": "super.img",
    "vendor_boot.img": "vendor_boot.img",
    "dtbo.img": "dtbo.img",
    "NON-HLOS.bin": "NON-HLOS.bin",
    "BTFM.bin": "BTFM.bin",
}
NIXPKGS_REV = "eaad089433ca2bb662274377d33df3d0e51ef28b"

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def nix_package_version(path, package):
    name = Path(path).name
    marker = f"-{package}-"
    if marker in name:
        return name.rsplit(marker, 1)[1]
    prefix = f"{package}-"
    if name.startswith(prefix):
        return name[len(prefix):]
    raise ValueError(f"Nix output path does not identify {package}: {name}")

CS35L41_EXPECTED_CONTROLS = (
    "MAX_LRCLK_DELAY", "CAL_R", "CAL_CHECKSUM", "CAL_STATUS",
    "CAL_R_SELECTED", "CAL_SET_STATUS", "CAL_AMBIENT",
)


def inspect_stock_wmfw(path):
    data = path.read_bytes()
    if len(data) < 40:
        raise RuntimeError(f"truncated CS35L41 WMFW: {path}")
    magic, header_length, revision, core, version = struct.unpack_from("<4sI H B B", data)
    if magic != b"WMFW" or header_length < 12 or header_length > len(data):
        raise RuntimeError(f"invalid CS35L41 WMFW header: {path}")
    if core != 4:
        raise RuntimeError(f"unexpected CS35L41 WMFW core: {core}")
    timestamp, checksum = struct.unpack_from("<QI", data, header_length - 12)
    controls = {name: name.encode("ascii") in data for name in CS35L41_EXPECTED_CONTROLS}
    if not all(controls.values()):
        raise RuntimeError(f"stock CS35L41 protection WMFW lacks required control symbols: {controls}")
    return {
        "source_path": "vendor_a:firmware/cs35l41-dsp1-spk-prot.wmfw",
        "format_magic": magic.decode("ascii"),
        "format_version": version,
        "header_revision": revision,
        "header_revision_hex": f"0x{revision:04x}",
        "dsp_core": "WMFW_HALO" if core == 4 else str(core),
        "header_length": header_length,
        "footer_timestamp": timestamp,
        "footer_timestamp_hex": f"0x{timestamp:016x}",
        "footer_checksum": checksum,
        "expected_control_symbols": controls,
        "target_documented_10251826_build":
            "v6.83.0/halo_cspl_RAM_revB2_29.85.0.wmfw (upstream filename/reference)",
        "target_build_label_present_as_ascii": b"29.85.0" in data,
        "comparison":
            "stock image exposes WMFW format/core/timestamp metadata; the documented build label "
            "is not embedded as ASCII, so no build equivalence is asserted",
    }


def run(args):
    subprocess.run(args, check=True)


def copy_file(src, destination, records, root, source_image, source_partition, source_path):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, destination)
    source_hash = sha256(src)
    destination_hash = sha256(destination)
    if source_hash != destination_hash:
        raise RuntimeError(f"byte-preserving copy checksum mismatch for {src}")
    records.append({
        "path": destination.relative_to(root).as_posix(), "source_image": source_image,
        "source_partition": source_partition, "source_path": source_path,
        "source_sha256": source_hash, "sha256": destination_hash,
        "size": destination.stat().st_size,
    })


def split_fdt_blob(blob, limit=None):
    """Split a concatenated flattened-device-tree blob by its big-endian totalsize."""
    offset = 0
    end = len(blob) if limit is None else min(len(blob), limit)
    while offset + 8 <= end:
        if blob[offset:offset + 4] != b"\xd0\x0d\xfe\xed":
            break
        size = struct.unpack_from(">I", blob, offset + 4)[0]
        if size < 40 or offset + size > end:
            raise ValueError(f"invalid FDT totalsize {size} at offset {offset}")
        yield blob[offset:offset + size]
        offset += size
    if offset != end and any(blob[offset:end]):
        raise ValueError(f"non-FDT bytes at end of DTB blob (offset {offset}, size {end})")


def fdt_symbols(path):
    blob = path.read_bytes()
    if len(blob) < 40:
        raise ValueError(f"truncated FDT: {path}")
    header = struct.unpack_from(">10I", blob)
    magic, total, struct_offset, strings_offset, _, _, _, _, strings_size, struct_size = header
    if magic != 0xD00DFEED or total > len(blob):
        raise ValueError(f"invalid FDT header: {path}")
    if (struct_offset + struct_size > total or strings_offset + strings_size > total):
        raise ValueError(f"FDT blocks exceed declared total size: {path}")
    structure = blob[struct_offset:struct_offset + struct_size]
    strings = blob[strings_offset:strings_offset + strings_size]
    cursor = 0
    nodes = []
    symbols = {}
    ended = False
    while cursor + 4 <= len(structure):
        token = struct.unpack_from(">I", structure, cursor)[0]
        cursor += 4
        if token == 1:  # FDT_BEGIN_NODE
            terminator = structure.find(b"\0", cursor)
            if terminator < 0:
                raise ValueError(f"unterminated FDT node name: {path}")
            nodes.append(structure[cursor:terminator].decode("ascii"))
            cursor = (terminator + 4) & ~3
        elif token == 2:  # FDT_END_NODE
            if not nodes:
                raise ValueError(f"unbalanced FDT node: {path}")
            nodes.pop()
        elif token == 3:  # FDT_PROP
            if cursor + 8 > len(structure):
                raise ValueError(f"truncated FDT property: {path}")
            length, name_offset = struct.unpack_from(">II", structure, cursor)
            cursor += 8
            end = cursor + length
            if end > len(structure) or name_offset >= len(strings):
                raise ValueError(f"FDT property exceeds block: {path}")
            name_end = strings.find(b"\0", name_offset)
            if name_end < 0:
                raise ValueError(f"unterminated FDT property name: {path}")
            name = strings[name_offset:name_end].decode("ascii")
            if nodes and nodes[-1] == "__symbols__":
                symbols[name] = structure[cursor:end].rstrip(b"\0").decode("utf-8")
            cursor = (end + 3) & ~3
        elif token == 4:  # FDT_NOP
            continue
        elif token == 9:  # FDT_END
            ended = True
            break
        else:
            raise ValueError(f"unknown FDT token {token}: {path}")
    if not ended:
        raise ValueError(f"missing FDT_END token: {path}")
    return symbols

def extract_dtbo(image, output, records, root):
    blob = image.read_bytes()
    if len(blob) < 32:
        raise ValueError("dtbo.img is shorter than its table header")
    magic, total, hsize, esize, count, entries, page, version = struct.unpack_from(">8I", blob)
    if magic != 0xD7B7AB1E or total > len(blob) or hsize < 32 or esize < 32:
        raise ValueError("unsupported or malformed Android DT table")
    if entries + count * esize > total:
        raise ValueError("DT table entry array exceeds table size")
    output.mkdir(parents=True, exist_ok=True)
    for index in range(count):
        entry = struct.unpack_from(">8I", blob, entries + index * esize)
        size, offset = entry[:2]
        if offset + size > total:
            raise ValueError(f"DTBO entry {index} exceeds table")
        data = blob[offset:offset + size]
        name = f"entry.{index:02d}.dtb"
        path = output / name
        path.write_bytes(data)
        data_hash = hashlib.sha256(data).hexdigest()
        records.append({"path": path.relative_to(root).as_posix(), "source_image": "dtbo.img",
                        "source_partition": "dtbo", "source_path": f"entry[{index}]",
                        "source_sha256": data_hash, "sha256": sha256(path), "size": len(data),
                        "dt_entry": {"id": entry[2], "rev": entry[3], "custom": entry[4:]}})
    return count



def copy_mtools_glob(image, pattern, destination, generated, records, image_name, partition_path,
                     rename_map=None):
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="liuqin-fat-") as temporary:
        extracted = Path(temporary)
        run(["mcopy", "-i", str(image), f"::/image/{pattern}", str(extracted)])
        for source in sorted(p for p in extracted.iterdir() if p.is_file()):
            target = destination / ((rename_map or {}).get(source.name, source.name))
            shutil.copyfile(source, target)
            source_hash = sha256(source)
            target_hash = sha256(target)
            if source_hash != target_hash:
                raise RuntimeError(f"mtools extraction checksum mismatch for {source.name}")
            records.append({"path": target.relative_to(generated).as_posix(),
                            "source_image": image_name, "source_partition": partition_path,
                            "source_path": f"image/{source.name}", "source_sha256": source_hash,
                            "sha256": target_hash, "size": target.stat().st_size})

def build_vendor_wlan(non_hlos, base_board, output_firmware, generated, records, temporary,
                      upstream_board_path):
    vendor = Path(temporary) / "qca6490"
    vendor.mkdir()
    for filename in ("amss20.bin", "m3.bin", "regdb.bin", "bd_m81gf.elf"):
        run(["mcopy", "-i", str(non_hlos), f"::/image/qca6490/{filename}", str(vendor)])
    inputs = {path.name: sha256(path) for path in sorted(vendor.iterdir())}

    encoder_url = ("https://raw.githubusercontent.com/qualcomm/qca-swiss-army-knife/"
                   "6df4dae3e2f5e4c2903f3cafd40996fc1b3639ce/"
                   "tools/scripts/ath11k/ath11k-bdencoder")
    encoder_sha256 = "11wyd9iq2ssrgbcx5m03gzmayjg3pfhslx9vfxh5vwvgdp8q28aa"
    expression = ("(builtins.fetchurl { url = " + json.dumps(encoder_url) +
                  "; sha256 = " + json.dumps(encoder_sha256) +
                  "; name = \"ath11k-bdencoder\"; })")
    encoder = Path(subprocess.check_output(
        ["nix", "eval", "--raw", "--expr", expression], text=True).strip())
    if not encoder.is_file():
        raise RuntimeError("pinned ath11k-bdencoder source did not resolve")

    work = Path(temporary) / "board"
    work.mkdir()
    upstream_board = work / "board-2.bin"
    if base_board.suffix == ".zst":
        with upstream_board.open("wb") as stream:
            subprocess.run(["zstd", "-qdc", str(base_board)], stdout=stream, check=True)
    else:
        shutil.copyfile(base_board, upstream_board)
    subprocess.run(["python3", str(encoder), "-e", upstream_board.name], cwd=work, check=True)
    manifest = work / "board-2.json"
    entries = json.loads(manifest.read_text())
    board_key = ("bus=pci,vendor=17cb,device=1103,subsystem-vendor=17cb,"
                 "subsystem-device=0108,qmi-chip-id=18,qmi-board-id=255")
    if not isinstance(entries, list) or len(entries) != 1:
        raise RuntimeError("unexpected upstream WCN6855 board container")
    matches = [entry for entry in entries[0]["board"] if board_key in entry["names"]]
    if len(matches) != 1 or matches[0]["names"] != [board_key]:
        raise RuntimeError("upstream board container does not have one isolated liuqin tuple")
    shutil.copyfile(vendor / "bd_m81gf.elf", work / "liuqin.elf")
    matches[0]["data"] = "liuqin.elf"
    manifest.write_text(json.dumps(entries, indent=4) + "\n")
    board_output = work / "liuqin-board.bin"
    subprocess.run(["python3", str(encoder), "-c", manifest.name, "-o", board_output.name],
                   cwd=work, check=True)
    derived = {
        "amss.bin": vendor / "amss20.bin",
        "board-2.bin": board_output,
        "m3.bin": vendor / "m3.bin",
        "regdb.bin": vendor / "regdb.bin",
    }
    base_board_hash = sha256(base_board)
    encoder_hash = sha256(encoder)
    board_hash = sha256(board_output)
    for prefix in ("updates/ath11k/WCN6855", "ath11k/WCN6855"):
        for hardware in ("hw2.0", "hw2.1"):
            destination_dir = output_firmware / prefix / hardware
            destination_dir.mkdir(parents=True, exist_ok=True)
            for name, source in derived.items():
                destination = destination_dir / name
                shutil.copyfile(source, destination)
                source_hash = sha256(source)
                output_hash = sha256(destination)
                if source_hash != output_hash:
                    raise RuntimeError(f"WLAN tuple copy checksum mismatch for {name}")
                records.append({"path": destination.relative_to(generated).as_posix(),
                                "source_image": "generated vendor WLAN tuple",
                                "source_partition": "NON-HLOS.bin QCA6490 + pinned upstream board data",
                                "source_path": f"{name}; inputs={json.dumps(inputs, sort_keys=True)}",
                                "source_sha256": source_hash, "sha256": output_hash,
                                "size": destination.stat().st_size})
    return {
        "vendor_inputs_sha256": inputs,
        "upstream_board": {"source": upstream_board_path, "sha256": base_board_hash},
        "bdencoder": {"repository": "https://github.com/qualcomm/qca-swiss-army-knife",
                      "commit": "6df4dae3e2f5e4c2903f3cafd40996fc1b3639ce",
                      "path": "tools/scripts/ath11k/ath11k-bdencoder",
                      "url": encoder_url, "sha256_base32": encoder_sha256,
                      "sha256_hex": encoder_hash,
                      "license": "Permissive license text embedded in the source"},
        "generator_sha256": sha256(Path(__file__)),
        "generated_board_sha256": board_hash,
        "generated_vendor_tuple_path": "assets/firmware/lib/firmware/{updates/,}ath11k/WCN6855/{hw2.0,hw2.1}",
    }
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images", required=True, type=Path)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--linux-firmware", required=True, type=Path)
    parser.add_argument("--wireless-regdb", required=True, type=Path)
    args = parser.parse_args()
    images = args.images.resolve()
    repo = args.repo.resolve()
    records, missing = [], []
    generated = Path(tempfile.mkdtemp(prefix="liuqin-os204-assets-"))
    atexit.register(lambda: shutil.rmtree(generated, ignore_errors=True))
    # Active super partitions plus explicitly named vendor containers only.
    # Never mount or inspect persist, userdata, cust, or per-device state.
    non_hlos = images / "NON-HLOS.bin"
    bt_firmware = images / "BTFM.bin"
    with tempfile.TemporaryDirectory(prefix="liuqin-os204-") as temporary:
        temp = Path(temporary)
        raw_super = temp / "super.raw"
        partitions = temp / "partitions"
        partitions.mkdir()
        run(["simg2img", str(images / "super.img"), str(raw_super)])
        run(["lpunpack", "-p", "vendor_a", "-p", "odm_a", str(raw_super), str(partitions)])
        extracted = {}
        for partition in ("vendor_a", "odm_a"):
            image = partitions / f"{partition}.img"
            if image.is_file() and image.stat().st_size:
                root = temp / f"{partition}.root"
                root.mkdir()
                run(["fsck.erofs", f"--extract={root}", str(image)])
                extracted[partition] = root

        vendor = extracted.get("vendor_a")
        if vendor is None:
            raise RuntimeError("official super image has no active vendor_a partition")

        firmware_root = args.linux_firmware / "lib/firmware"
        linux_firmware_version = nix_package_version(args.linux_firmware, "linux-firmware")
        wireless_regdb_version = nix_package_version(args.wireless_regdb, "wireless-regdb")
        output_firmware = generated / "assets/firmware/lib/firmware"
        upstream_board_source = None
        wlan_provenance = None
        for hardware in ("hw2.0", "hw2.1"):
            upstream_dir = firmware_root / "ath11k/WCN6855" / hardware
            for filename in ("amss.bin", "board-2.bin", "m3.bin", "regdb.bin"):
                candidates = (upstream_dir / (filename + ".zst"), upstream_dir / filename)
                source = next((candidate for candidate in candidates if candidate.is_file()), None)
                if source is None:
                    missing.append({"path": f"assets/firmware/lib/firmware/ath11k/WCN6855/{hardware}/{filename}",
                                    "searched": ["lib/firmware/" + candidate.relative_to(firmware_root).as_posix()
                                                 for candidate in candidates],
                                    "reason": "not found in pinned Nixpkgs linux-firmware output"})
                    continue
                if hardware == "hw2.0" and filename == "board-2.bin":
                    upstream_board_source = source
                relative = Path("ath11k/WCN6855") / hardware / source.name
                if source.suffix == ".zst":
                    copy_file(source, output_firmware / relative, records, generated,
                              f"nixpkgs linux-firmware-{linux_firmware_version}@{NIXPKGS_REV}", "lib/firmware",
                              "lib/firmware/" + relative.as_posix())
                else:
                    source_hash = sha256(source)
                    source_path = "lib/firmware/" + source.relative_to(firmware_root).as_posix()
                    compressed = output_firmware / "ath11k/WCN6855" / hardware / (filename + ".zst")
                    compressed.parent.mkdir(parents=True, exist_ok=True)
                    with source.open("rb") as input_stream, compressed.open("wb") as stream:
                        subprocess.run(["zstd", "-q", "-19", "-c"], stdin=input_stream,
                                       stdout=stream, check=True)
                    records.append({"path": compressed.relative_to(generated).as_posix(),
                                    "source_image": f"nixpkgs linux-firmware-{linux_firmware_version}@{NIXPKGS_REV}",
                                    "source_partition": "compressed from pinned uncompressed upstream file",
                                    "source_path": source_path, "source_sha256": source_hash,
                                    "sha256": sha256(compressed), "size": compressed.stat().st_size})

        for filename in ("regulatory.db", "regulatory.db.p7s"):
            source = args.wireless_regdb / "lib/firmware" / filename
            if source.is_file():
                copy_file(source, output_firmware / filename, records, generated,
                          f"nixpkgs wireless-regdb-{wireless_regdb_version}@{NIXPKGS_REV}", "lib/firmware",
                          "lib/firmware/" + filename)
            else:
                missing.append({"path": f"assets/firmware/lib/firmware/{filename}",
                                "searched": ["lib/firmware/" + filename],
                                "reason": "not found in pinned Nixpkgs wireless-regdb output"})
        if upstream_board_source is not None:
            wlan_provenance = build_vendor_wlan(
                non_hlos, upstream_board_source, output_firmware, generated, records, temp,
                "lib/firmware/" + upstream_board_source.relative_to(firmware_root).as_posix())
        else:
            missing.append({"path": "assets/firmware/lib/firmware/updates/ath11k/WCN6855",
                            "searched": ["lib/firmware/ath11k/WCN6855/hw2.0/board-2.bin{,.zst}"],
                            "reason": "WLAN board generator requires upstream WCN6855 base board data"})

        # Official proprietary/non-redistributable modem and OEM firmware payloads.
        # These are ordinary image payloads; no persist content is read.
        dsp_dir = generated / "assets/firmware/lib/firmware/qcom/sm8475/liuqin"
        for dsp in ("adsp", "cdsp", "slpi"):
            copy_mtools_glob(non_hlos, f"{dsp}.mdt", dsp_dir, generated, records,
                             "NON-HLOS.bin", "FAT:image", {f"{dsp}.mdt": f"{dsp}.mbn"})
            copy_mtools_glob(non_hlos, f"{dsp}.b*", dsp_dir, generated, records,
                             "NON-HLOS.bin", "FAT:image")
        fpc_dir = generated / "assets/fingerprint"
        copy_mtools_glob(non_hlos, "fpcliu.*", fpc_dir, generated, records,
                         "NON-HLOS.bin", "FAT:image")

        # Bluetooth HSP firmware and public vendor NVM from the official BTFM image.
        qca_dir = generated / "assets/firmware/lib/firmware/qca"
        for pattern in ("hpbtfw20.*", "hpbtfw21.*", "hpnv20.*", "hpnv20g.*",
                        "hpnv21.*", "hpnv21g.*"):
            copy_mtools_glob(bt_firmware, pattern, qca_dir, generated, records,
                             "BTFM.bin", "FAT:image")
        for source in sorted(qca_dir.glob("hp*")):
            target = qca_dir / ("wcn" + source.name)
            shutil.copyfile(source, target)
            source_hash = sha256(source)
            target_hash = sha256(target)
            records.append({"path": target.relative_to(generated).as_posix(),
                            "source_image": "BTFM.bin", "source_partition": "FAT:image",
                            "source_path": source.name + " (same bytes, WCN loader alias)",
                            "source_sha256": source_hash, "sha256": target_hash,
                            "size": target.stat().st_size})

        # Paths consumed from the stock vendor firmware tree.
        firmware_map = {
            "firmware/novatek_nt36532_m81_fw_csot.bin": "novatek/liuqin/novatek_nt36532_m81_fw_csot.bin",
            "firmware/novatek_nt36532_m81_fw_tm.bin": "novatek/liuqin/novatek_nt36532_m81_fw_tm.bin",
            "firmware/a730_zap.mdt": "qcom/a730_zap.mbn",
            "firmware/a730_sqe.fw": "qcom/a730_sqe.fw",
            "firmware/gmu_gen70000.bin": "qcom/gmu_gen70000.bin",
            "firmware/vpu20_4v.mbn": "qcom/vpu/vpu20_4v.mbn",
            "firmware/cs35l41-dsp1-spk-cali.wmfw": "cirrus/cs35l41-dsp1-spk-cali.wmfw",
            "firmware/cs35l41-dsp1-spk-prot.wmfw": "cirrus/cs35l41-dsp1-spk-prot.wmfw",
            "firmware/BL-cs35l41-dsp1-spk-cali.bin": "cirrus/BL-cs35l41-dsp1-spk-cali.bin",
            "firmware/BL-cs35l41-dsp1-spk-prot.bin": "cirrus/BL-cs35l41-dsp1-spk-prot.bin",
            "firmware/BR-cs35l41-dsp1-spk-cali.bin": "cirrus/BR-cs35l41-dsp1-spk-cali.bin",
            "firmware/BR-cs35l41-dsp1-spk-prot.bin": "cirrus/BR-cs35l41-dsp1-spk-prot.bin",
            "firmware/TL-cs35l41-dsp1-spk-cali.bin": "cirrus/TL-cs35l41-dsp1-spk-cali.bin",
            "firmware/TL-cs35l41-dsp1-spk-prot.bin": "cirrus/TL-cs35l41-dsp1-spk-prot.bin",
            "firmware/TR-cs35l41-dsp1-spk-cali.bin": "cirrus/TR-cs35l41-dsp1-spk-cali.bin",
            "firmware/TR-cs35l41-dsp1-spk-prot.bin": "cirrus/TR-cs35l41-dsp1-spk-prot.bin",
        }
        for src_rel, dest_rel in firmware_map.items():
            source_partition = next(
                (name for name in ("vendor_a", "odm_a")
                 if (extracted.get(name) is not None and (extracted[name] / src_rel).is_file())),
                None)
            destination = generated / "assets/firmware/lib/firmware" / dest_rel
            if source_partition is not None:
                source = extracted[source_partition] / src_rel
                copy_file(source, destination, records, generated, "super.img",
                          source_partition, src_rel)
            else:
                missing.append({"path": destination.relative_to(generated).as_posix(),
                                "searched": [f"vendor_a:{src_rel}", f"odm_a:{src_rel}"],
                                "reason": "not present in extracted official OS2.0.4 active partitions"})

        # Qualcomm's MDT is only metadata; each PT_LOAD segment is fetched as
        # a sibling .bNN file by qcom_mdt_load(). Keep the complete stock set
        # together rather than publishing an unusable metadata file alone.
        zap_partition = next(
            (name for name in ("vendor_a", "odm_a")
             if (extracted.get(name) is not None
                 and (extracted[name] / "firmware/a730_zap.mdt").is_file())),
            None)
        zap_segments = (
            sorted((extracted[zap_partition] / "firmware").glob("a730_zap.b[0-9][0-9]"))
            if zap_partition is not None else []
        )
        if not zap_segments:
            raise RuntimeError(
                "a730_zap.mdt has no a730_zap.bNN load segments in the same stock partition")
        for source in zap_segments:
            copy_file(source, output_firmware / "qcom" / source.name, records, generated,
                      "super.img", zap_partition, f"firmware/{source.name}")

        # This SKU-specific loader name aliases the identical stock generic Halo image.
        cs35l41_wmfw_metadata = None
        stock_prot_wmfw = vendor / "firmware/cs35l41-dsp1-spk-prot.wmfw"
        if stock_prot_wmfw.is_file():
            cs35l41_wmfw_metadata = inspect_stock_wmfw(stock_prot_wmfw)
            alias = generated / "assets/firmware/lib/firmware/cirrus/cs35l41-dsp1-spk-prot-10251826.wmfw"
            copy_file(stock_prot_wmfw, alias, records, generated, "super.img", "vendor_a",
                      "firmware/cs35l41-dsp1-spk-prot.wmfw (byte-identical alias-of generic stock file)")
        for prefix, position in (("TL", "tl"), ("TR", "tr"), ("BR", "br"), ("BL", "bl")):
            stock_bin = vendor / f"firmware/{prefix}-cs35l41-dsp1-spk-prot.bin"
            if stock_bin.is_file():
                alias = generated / "assets/firmware/lib/firmware/cirrus" / (
                    f"cs35l41-dsp1-spk-prot-10251826-{position}.bin")
                copy_file(stock_bin, alias, records, generated, "super.img", "vendor_a",
                          f"firmware/{prefix}-cs35l41-dsp1-spk-prot.bin (byte-identical alias-of position stock file)")
            else:
                missing.append({"path": f"assets/firmware/lib/firmware/cirrus/cs35l41-dsp1-spk-prot-10251826-{position}.bin",
                                "searched": [f"vendor_a:firmware/{prefix}-cs35l41-dsp1-spk-prot.bin"],
                                "reason": "matching per-position stock CS35L41 protection coefficient absent"})

        # Copy complete upstream stock static sensor configuration directory and registry config.
        sensor_dir = vendor / "etc/sensors/config"
        if sensor_dir.is_dir():
            for source in sorted(p for p in sensor_dir.rglob("*") if p.is_file()):
                rel = source.relative_to(vendor).as_posix()
                destination = generated / "assets/sensors" / rel
                copy_file(source, destination, records, generated, "super.img", "vendor_a", rel)
        for rel in ("etc/sensors/sns_reg.conf", "etc/sensors/sns_reg_version", "etc/sensors/sns_reg_config"):
            source_partition = next(
                (name for name in ("vendor_a", "odm_a")
                 if (extracted.get(name) is not None and (extracted[name] / rel).is_file())),
                None)
            if source_partition is not None:
                source = extracted[source_partition] / rel
                destination = generated / "assets/sensors" / rel
                copy_file(source, destination, records, generated, "super.img",
                          source_partition, rel)
            else:
                item = {"path": "assets/sensors/" + rel,
                        "searched": ["vendor_a:etc/sensors", "odm_a:etc/sensors"],
                        "reason": "file absent from official OS2.0.4"}
                if rel in ("etc/sensors/sns_reg.conf", "etc/sensors/sns_reg_version"):
                    item["optional"] = True
                missing.append(item)
        if not sensor_dir.is_dir():
            missing.append({"path": "assets/sensors/etc/sensors/config",
                            "searched": ["vendor_a:etc/sensors/config"],
                            "reason": "required stock sensor configuration directory is absent"})

        # Bootloader inputs: vendor_boot's concatenated base DTB array and dtbo table entries.
        vb = temp / "vendor_boot"
        vb.mkdir()
        run(["unpack_bootimg", "--boot_img", str(images / "vendor_boot.img"), "--out", str(vb)])
        dtb = vb / "dtb"
        base_out = generated / "assets/bootimg/stock-base-dtbs"
        base_out.mkdir(parents=True, exist_ok=True)
        base_blob = dtb.read_bytes()
        base_dtbs = list(split_fdt_blob(base_blob))
        for index, data in enumerate(base_dtbs):
            destination = base_out / f"dtb-{index}.dtb"
            destination.write_bytes(data)
            records.append({"path": destination.relative_to(generated).as_posix(), "source_image": "vendor_boot.img",
                            "source_partition": "vendor_boot", "source_path": f"dtb[{index}]",
                            "source_sha256": hashlib.sha256(data).hexdigest(),
                            "sha256": sha256(destination), "size": len(data)})
        if len(base_dtbs) != 14:
            missing.append({"path": "assets/bootimg/stock-base-dtbs", "expected_count": 14,
                            "actual_count": len(base_dtbs), "reason": "unexpected vendor_boot DTB count"})
        dtbo_out = generated / "assets/bootimg/stock-dtbo-entries"
        dtbo_count = extract_dtbo(images / "dtbo.img", dtbo_out, records, generated)
        dtbo_paths = sorted(dtbo_out.glob("entry.*.dtb"))
        if len(dtbo_paths) != dtbo_count:
            missing.append({"path": "assets/bootimg/stock-dtbo-entries",
                            "expected_count": dtbo_count, "actual_count": len(dtbo_paths),
                            "reason": "extracted DTBO entry count differs from source table"})
        base_dtb_symbols = {
            path.name: fdt_symbols(path) for path in sorted(base_out.glob("dtb-*.dtb"))
        }
        dtbo_symbols = {path.name: fdt_symbols(path) for path in dtbo_paths}
        symbol_union = sorted(
            set().union(*(set(symbols) for symbols in base_dtb_symbols.values()),
                        *(set(symbols) for symbols in dtbo_symbols.values())))
        bootimg_metadata = {
            "base_dtb_count": len(base_dtbs),
            "dtbo_entry_count": len(dtbo_paths),
            "base_dtb_symbols": base_dtb_symbols,
            "dtbo_symbols": dtbo_symbols,
            "symbol_union": symbol_union,
        }

        # Build the open AudioReach topology from the immutable upstream commit.
        audio_commit = "2af1f1ebb8d4fd03b5f53891467ddde2e208a8a0"
        audio_source = temp / "audioreach-topology"
        run(["git", "clone", "--no-checkout",
             "https://github.com/linux-msm/audioreach-topology.git", str(audio_source)])
        run(["git", "-C", str(audio_source), "fetch", "--depth", "1", "origin", audio_commit])
        run(["git", "-C", str(audio_source), "checkout", "--detach", "FETCH_HEAD"])
        topology = output_firmware / "qcom/sm8450/Xiaomi-Pad-6-Pro-tplg.bin"
        env = os.environ.copy()
        env["AUDIOREACH_TOPOLOGY_DIR"] = str(audio_source)
        env["OUTPUT"] = str(topology)
        subprocess.run(["sh", str(repo / "scripts/build-audio-topology.sh")],
                       env=env, check=True)
        topology_record = {"path": topology.relative_to(generated).as_posix(),
                           "source_image": "generated AudioReach topology",
                           "source_partition": f"linux-msm/audioreach-topology@{audio_commit}",
                           "source_path": "scripts/audio-topology/liuqin-speakers.m4",
                           "sha256": sha256(topology), "size": topology.stat().st_size}
        records.append(topology_record)

        fingerprint = generated / "assets/fingerprint"
        fp_files = sorted(fingerprint.glob("fpcliu.*"))
        if fp_files:
            fp_sha = {path.name: sha256(path) for path in fp_files}
            fingerprint_sha = fingerprint / "SHA256.json"
            fingerprint_sha.write_text(json.dumps(fp_sha, indent=2, sort_keys=True) + "\n")
            records.append({"path": fingerprint_sha.relative_to(generated).as_posix(),
                            "source_image": "generated", "source_partition": "SHA256 manifest",
                            "source_path": "fpcliu.* extracted from NON-HLOS.bin",
                            "sha256": sha256(fingerprint_sha), "size": fingerprint_sha.stat().st_size})
        else:
            missing.append({"path": "assets/fingerprint/fpcliu.*",
                            "searched": ["NON-HLOS.bin:FAT:image/fpcliu.*"],
                            "reason": "optional FPC1264 OEM firmware was not found",
                            "optional": True})

        firmware_files = sorted(p for p in output_firmware.rglob("*") if p.is_file())
        firmware_checksums = generated / "assets/firmware/SHA256SUMS"
        firmware_checksums.parent.mkdir(parents=True, exist_ok=True)
        firmware_checksums.write_text("".join(
            f"{sha256(path)}  {path.relative_to(output_firmware).as_posix()}\n"
            for path in firmware_files))
        records.append({"path": firmware_checksums.relative_to(generated).as_posix(),
                        "source_image": "generated", "source_partition": "firmware checksums",
                        "source_path": "assets/firmware/lib/firmware",
                        "sha256": sha256(firmware_checksums), "size": firmware_checksums.stat().st_size})

    required_missing = [item for item in missing if not item.get("optional", False)]
    if required_missing:
        for item in required_missing:
            print(f"MISSING {item['path']}: {item['reason']}", file=sys.stderr)
            if item.get("searched"):
                print(f"  searched: {', '.join(item['searched'])}", file=sys.stderr)
        raise RuntimeError("required OS2.0.4 inputs are missing; assets and manifests were not updated")
    assets = repo / "assets"
    if assets.exists():
        shutil.rmtree(assets)
    shutil.copytree(generated / "assets", assets)
    image_records = []
    for name in SOURCE_IMAGES:
        path = images / name
        image_records.append({"image": name, "path": name, "size": path.stat().st_size,
                              "sha256": sha256(path)})
    audio_commit = "2af1f1ebb8d4fd03b5f53891467ddde2e208a8a0"
    manifest = {
        "format": 1,
        "source": {"package": "Xiaomi OS2.0.4.0.VMYCNXM_15.0", "images_directory": "images",
                   "images": image_records,
                   "nixpkgs_revision": NIXPKGS_REV,
                   "upstream_outputs": {
                       "linux-firmware": {
                           "version": linux_firmware_version,
                           "path": "lib/firmware",
                       },
                       "wireless-regdb": {
                           "version": wireless_regdb_version,
                           "path": "lib/firmware",
                       },
                   }},
        "provenance": {
            "license": "OEM firmware is proprietary and non-redistributable; do not publish without authorization",
            "upstream_firmware": {
                "nixpkgs_revision": NIXPKGS_REV,
                "linux_firmware_license": "per-file licensing is supplied by the locked linux-firmware source WHENCE",
                "wireless_regdb_license": "ISC (as declared by the locked Nixpkgs package)",
            },
            "audio_topology": {
                "repository": "https://github.com/linux-msm/audioreach-topology",
                "commit": audio_commit,
                "license": "BSD-3-Clause",
                "board_source": "scripts/audio-topology/liuqin-speakers.m4",
                "board_source_sha256": sha256(repo / "scripts/audio-topology/liuqin-speakers.m4"),
                "builder_sha256": sha256(repo / "scripts/build-audio-topology.sh"),
                "output_sha256": topology_record["sha256"],
            },
            "cs35l41_aliases": {
                "cirrus/cs35l41-dsp1-spk-prot-10251826.wmfw":
                    "vendor_a:firmware/cs35l41-dsp1-spk-prot.wmfw (byte-identical)",
                "cirrus/cs35l41-dsp1-spk-prot-10251826-{tl,tr,br,bl}.bin":
                    "matching vendor_a:firmware/{TL,TR,BR,BL}-cs35l41-dsp1-spk-prot.bin (byte-identical)",
            },
            "source_name_mappings": {
                "qcom/a730_zap.mbn":
                    "super.img:vendor_a:firmware/a730_zap.mdt; filename-only rename, "
                    "byte identity verified by source/output SHA256",
            },
            "cs35l41_stock_protection_wmfw": cs35l41_wmfw_metadata,
            "wlan": wlan_provenance,
        },
        "extraction": {"tools": ["android-tools", "erofs-utils", "mtools", "zstd", "git", "m4", "alsa-utils"],
                       "partition_scope": ["super.img:vendor_a", "super.img:odm_a",
                                           "NON-HLOS.bin:FAT:image", "BTFM.bin:FAT:image"],
                       "excluded": ["persist", "userdata", "cust", "downstream release images", "private device state"]},
        "bootimg": bootimg_metadata,
        "outputs": sorted(records, key=lambda x: x["path"]),
        "missing": missing,
    }
    manifest_path = assets / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    tsv = ["source_image\tsource_partition\tsource_path\toutput\tsource_sha256\tsha256\tbytes"]
    for record in sorted(records, key=lambda entry: entry["path"]):
        fields = (record.get("source_image", ""), record.get("source_partition", ""),
                  record.get("source_path", ""), record["path"], record.get("source_sha256", ""),
                  record["sha256"], str(record["size"]))
        tsv.append("\t".join(value.replace("\t", " ").replace("\n", " ") for value in fields))
    (repo / "MANIFEST.tsv").write_text("\n".join(tsv) + "\n")
    print(f"Wrote {len(records)} payload records; {len(missing)} unresolved/missing records.")
    print(f"Manifest: {manifest_path}")
    for item in missing:
        print(f"MISSING {item['path']}: {item['reason']}")


if __name__ == "__main__":
    main()
