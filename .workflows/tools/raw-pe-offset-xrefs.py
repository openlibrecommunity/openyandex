#!/usr/bin/env python3
"""Find raw PE references to known file offsets.

This covers cases where Ghidra analysis did not define string Data objects, so
defined-string xref export returns no rows. For each file offset, the script
maps it to RVA/VA and scans the PE for little-endian references to the VA, RVA,
and file offset. Hits are annotated with the containing Ghidra function when
available from exported function-diff facts.
"""

import argparse
import bisect
import json
import struct
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FACTS = ROOT / ".workflows" / "active-stage" / "exports" / "yandex_browser_dll.function-diff-facts.jsonl"


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def parse_pe(data):
    if data[:2] != b"MZ":
        raise ValueError("not a PE/MZ file")
    pe = read_u32(data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    file_header = pe + 4
    section_count = read_u16(data, file_header + 2)
    optional_size = read_u16(data, file_header + 16)
    optional = file_header + 20
    magic = read_u16(data, optional)
    if magic == 0x10B:
        image_base = read_u32(data, optional + 28)
    elif magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    else:
        raise ValueError(f"unsupported optional header magic: {magic:#x}")
    sections = []
    section_off = optional + optional_size
    for i in range(section_count):
        off = section_off + i * 40
        name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size = read_u32(data, off + 8)
        virtual_address = read_u32(data, off + 12)
        raw_size = read_u32(data, off + 16)
        raw_ptr = read_u32(data, off + 20)
        sections.append({
            "name": name,
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "raw_size": raw_size,
            "raw_ptr": raw_ptr,
        })
    return image_base, sections


def fileoff_to_rva(fileoff, sections):
    for sec in sections:
        raw_start = sec["raw_ptr"]
        raw_end = raw_start + max(sec["raw_size"], 0)
        if raw_start <= fileoff < raw_end:
            return sec["virtual_address"] + (fileoff - raw_start), sec["name"]
    return None, None


def fileoff_to_va(fileoff, image_base, sections):
    rva, section = fileoff_to_rva(fileoff, sections)
    if rva is None:
        return None, None, None
    return image_base + rva, rva, section


def iter_hits(data, needle):
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            return
        yield idx
        start = idx + 1


def read_functions(path):
    funcs = []
    if not path.exists():
        return [], []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("schema") != "ghidra_function_diff_fact":
                continue
            d = row.get("data", {})
            entry = d.get("entry")
            size = d.get("body_size") or 0
            if not entry or not size:
                continue
            try:
                start = int(entry, 16)
            except ValueError:
                continue
            funcs.append((start, start + int(size), d.get("name") or "", entry))
    funcs.sort()
    starts = [f[0] for f in funcs]
    return funcs, starts


def containing_function(va, funcs, starts):
    idx = bisect.bisect_right(starts, va) - 1
    if idx < 0:
        return None
    start, end, name, entry = funcs[idx]
    if start <= va < end:
        return {"function": name, "function_entry": entry}
    return None


def make_row(schema, artifact, data):
    return {
        "schema": schema,
        "schema_version": 1,
        "artifact": artifact,
        "artifact_sha256": None,
        "collected_at_utc": now(),
        "extractor": "openyandex-raw-pe-offset-xrefs",
        "extractor_version": "python3-v1",
        "command": ".workflows/tools/raw-pe-offset-xrefs.py",
        "confidence": 0.7,
        "data": data,
    }


def parse_target(raw):
    if "=" not in raw:
        raise argparse.ArgumentTypeError("target must be label=file_offset")
    label, off = raw.split("=", 1)
    try:
        fileoff = int(off, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"bad file offset: {off}") from exc
    return label, fileoff


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("targets", nargs="+", type=parse_target)
    parser.add_argument("--function-facts", type=Path, default=DEFAULT_FACTS)
    args = parser.parse_args()

    data = args.binary.read_bytes()
    image_base, sections = parse_pe(data)
    funcs, starts = read_functions(args.function_facts)
    artifact = str(args.binary.relative_to(ROOT)) if args.binary.is_relative_to(ROOT) else str(args.binary)

    rows = []
    rows.append(make_row("raw_pe_image", artifact, {"image_base": image_base, "sections": sections}))
    for label, target_fileoff in args.targets:
        target_va, target_rva, target_section = fileoff_to_va(target_fileoff, image_base, sections)
        target = {
            "label": label,
            "target_file_offset": target_fileoff,
            "target_rva": target_rva,
            "target_va": target_va,
            "target_section": target_section,
        }
        rows.append(make_row("raw_pe_offset_target", artifact, target))
        if target_va is None:
            continue
        patterns = [
            ("u32_va", struct.pack("<I", target_va & 0xFFFFFFFF), target_va),
            ("u32_rva", struct.pack("<I", target_rva & 0xFFFFFFFF), target_rva),
            ("u32_file_offset", struct.pack("<I", target_fileoff & 0xFFFFFFFF), target_fileoff),
        ]
        if target_va > 0xFFFFFFFF:
            patterns.append(("u64_va", struct.pack("<Q", target_va), target_va))
        seen = set()
        for ref_kind, needle, encoded_value in patterns:
            for hit_fileoff in iter_hits(data, needle):
                key = (ref_kind, hit_fileoff)
                if key in seen:
                    continue
                seen.add(key)
                hit_va, hit_rva, hit_section = fileoff_to_va(hit_fileoff, image_base, sections)
                fn = containing_function(hit_va, funcs, starts) if hit_va is not None else None
                row_data = {
                    "label": label,
                    "ref_kind": ref_kind,
                    "encoded_value": encoded_value,
                    "target_file_offset": target_fileoff,
                    "target_rva": target_rva,
                    "target_va": target_va,
                    "ref_file_offset": hit_fileoff,
                    "ref_rva": hit_rva,
                    "ref_va": hit_va,
                    "ref_section": hit_section,
                }
                if fn:
                    row_data.update(fn)
                rows.append(make_row("raw_pe_offset_xref", artifact, row_data))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    print(args.out.relative_to(ROOT) if args.out.is_relative_to(ROOT) else args.out)


if __name__ == "__main__":
    main()
