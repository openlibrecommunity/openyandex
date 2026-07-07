#!/usr/bin/env python3
"""Run quick static-only triage for selected widget ELF files."""

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WIDGETS = ROOT / "artifacts" / "binaries" / "yandex-browser-25.6.0.2372" / "payload" / "Browser-bin" / "25.6.0.2372" / "widgets"
LOGS = ROOT / ".workflows" / "active-stage" / "logs"
EXPORTS = ROOT / ".workflows" / "active-stage" / "exports"
META = ROOT / ".workflows" / "metadata"
OUT = META / "active-widget-elf-triage.jsonl"

TARGETS = [
    "neuroedit_bubble.so",
    "neuro_question_bubble.so",
    "coupons_bubble.so",
    "flutter_components_demo.so",
    "suggest.so",
]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, out, timeout=120):
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as f:
        try:
            proc = subprocess.run(cmd, cwd=ROOT, stdout=f, stderr=subprocess.STDOUT, timeout=timeout, check=False)
            return proc.returncode
        except subprocess.TimeoutExpired:
            f.write(f"\nTIMEOUT after {timeout} seconds\n".encode())
            return 124


def text(path, limit=2_000_000):
    if not path.exists():
        return ""
    return path.read_bytes()[:limit].decode("utf-8", errors="replace")


def first_match(pattern, value):
    m = re.search(pattern, value, flags=re.MULTILINE)
    return m.group(1).strip() if m else None


def triage(name):
    path = WIDGETS / name
    stem = name.replace(".", "_")
    log = LOGS / stem
    exp = EXPORTS / stem
    commands = {
        "file": (["file", str(path)], log.with_suffix(".file.txt"), 60),
        "readelf-header": (["readelf", "-h", str(path)], log.with_suffix(".readelf-header.txt"), 60),
        "readelf-notes": (["readelf", "-n", str(path)], log.with_suffix(".readelf-notes.txt"), 60),
        "readelf-sections": (["readelf", "-S", str(path)], log.with_suffix(".readelf-sections.txt"), 60),
        "readelf-dynamic": (["readelf", "-d", str(path)], log.with_suffix(".readelf-dynamic.txt"), 60),
        "readelf-dynsyms": (["readelf", "--dyn-syms", str(path)], log.with_suffix(".readelf-dynsyms.txt"), 120),
        "rz-bin-info": (["rz-bin", "-I", str(path)], log.with_suffix(".rz-bin-info.txt"), 60),
        "rz-bin-imports": (["rz-bin", "-i", str(path)], log.with_suffix(".rz-bin-imports.txt"), 60),
        "rz-bin-exports": (["rz-bin", "-E", str(path)], log.with_suffix(".rz-bin-exports.txt"), 60),
        "strings": (["strings", "-a", "-n", "8", str(path)], exp.with_suffix(".strings.txt"), 120),
    }
    logs = {}
    rcs = {}
    for key, (cmd, out, timeout) in commands.items():
        rcs[key] = run(cmd, out, timeout)
        logs[key] = out.relative_to(ROOT).as_posix()

    note_text = text(log.with_suffix(".readelf-notes.txt"))
    dyn_text = text(log.with_suffix(".readelf-dynamic.txt"))
    strings_text = text(exp.with_suffix(".strings.txt"))
    needed = re.findall(r"Shared library: \[(.*?)\]", dyn_text)
    hits = [needle for needle in ["yandex", "alice", "neuro", "suggest", "coupon", "price", "http://", "https://", "json", "protobuf", "dart", "flutter"] if needle in strings_text.lower()]
    return {
        "schema": "active_widget_elf_static_triage",
        "schema_version": 1,
        "artifact": path.relative_to(ROOT).as_posix(),
        "artifact_sha256": sha256(path),
        "collected_at_utc": now(),
        "extractor": "openyandex-static-elf-widget-triage",
        "extractor_version": "python3-v1",
        "command": ".workflows/tools/static-elf-widget-triage.py",
        "confidence": 0.9,
        "data": {
            "name": name,
            "size": path.stat().st_size,
            "build_id": first_match(r"Build ID:\s*([^\n]+)", note_text),
            "needed_libraries": needed,
            "string_hit_categories": hits,
            "logs": logs,
            "returncodes": rcs,
        },
    }


def main():
    LOGS.mkdir(parents=True, exist_ok=True)
    EXPORTS.mkdir(parents=True, exist_ok=True)
    META.mkdir(parents=True, exist_ok=True)
    rows = []
    for name in TARGETS:
        print(f"triage {name}")
        rows.append(triage(name))
    with OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    print(OUT.relative_to(ROOT))


if __name__ == "__main__":
    main()
