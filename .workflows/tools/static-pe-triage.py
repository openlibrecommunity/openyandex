#!/usr/bin/env python3
"""Run static-only PE triage for selected artifacts."""

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PAYLOAD = ROOT / "artifacts" / "binaries" / "yandex-browser-25.6.0.2372" / "payload"
LOGS = ROOT / ".workflows" / "active-stage" / "logs"
EXPORTS = ROOT / ".workflows" / "active-stage" / "exports"
META = ROOT / ".workflows" / "metadata"
OUT = META / "active-pe-triage.jsonl"

TARGETS = {
    "service_update.exe": PAYLOAD / "Browser-bin" / "25.6.0.2372" / "service_update.exe",
    "cspeechkit.dll": PAYLOAD / "Browser-bin" / "25.6.0.2372" / "cspeechkit.dll",
    "speechkit_action_lib.dll": PAYLOAD / "Browser-bin" / "25.6.0.2372" / "speechkit_action_lib.dll",
    "textclassifier.dll": PAYLOAD / "Browser-bin" / "25.6.0.2372" / "textclassifier.dll",
}


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_to_file(cmd, out_path, timeout=900):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as f:
        try:
            proc = subprocess.run(cmd, cwd=ROOT, stdout=f, stderr=subprocess.STDOUT, timeout=timeout, check=False)
            return proc.returncode
        except subprocess.TimeoutExpired:
            f.write(f"\nTIMEOUT after {timeout} seconds\n".encode("utf-8"))
            return 124


def read_first_text(path, limit=4096):
    if not path.exists():
        return ""
    data = path.read_bytes()[:limit]
    return data.decode("utf-8", errors="replace")


def summarize_text(path, needles):
    text = read_first_text(path, 2_000_000).lower()
    return [needle for needle in needles if needle.lower() in text]


def triage(name, path):
    rel = path.relative_to(ROOT).as_posix()
    stem = name.replace(".", "_")
    log_prefix = LOGS / stem
    export_prefix = EXPORTS / stem
    logs = {}
    commands = [
        ("file", ["file", str(path)], log_prefix.with_suffix(".file.txt"), 60),
        ("exiftool", ["exiftool", str(path)], log_prefix.with_suffix(".exiftool.txt"), 120),
        ("osslsigncode", ["osslsigncode", "verify", str(path)], log_prefix.with_suffix(".osslsigncode.txt"), 120),
        ("diec", ["diec", str(path)], log_prefix.with_suffix(".diec.txt"), 120),
        ("llvm-readobj-file-headers", ["llvm-readobj", "--file-headers", str(path)], log_prefix.with_suffix(".llvm-readobj-file-headers.txt"), 120),
        ("llvm-readobj-sections", ["llvm-readobj", "--sections", str(path)], log_prefix.with_suffix(".llvm-readobj-sections.txt"), 120),
        ("llvm-readobj-imports", ["llvm-readobj", "--coff-imports", str(path)], log_prefix.with_suffix(".llvm-readobj-imports.txt"), 120),
        ("llvm-readobj-exports", ["llvm-readobj", "--coff-exports", str(path)], log_prefix.with_suffix(".llvm-readobj-exports.txt"), 120),
        ("llvm-readobj-codeview", ["llvm-readobj", "--codeview", str(path)], log_prefix.with_suffix(".llvm-readobj-codeview.txt"), 120),
        ("rz-bin-info", ["rz-bin", "-I", str(path)], log_prefix.with_suffix(".rz-bin-info.txt"), 120),
        ("rz-bin-sections", ["rz-bin", "-S", str(path)], log_prefix.with_suffix(".rz-bin-sections.txt"), 120),
        ("rz-bin-imports", ["rz-bin", "-i", str(path)], log_prefix.with_suffix(".rz-bin-imports.txt"), 120),
        ("rz-bin-exports", ["rz-bin", "-E", str(path)], log_prefix.with_suffix(".rz-bin-exports.txt"), 120),
        ("strings-ascii", ["strings", "-a", "-n", "8", str(path)], export_prefix.with_suffix(".strings-ascii.txt"), 120),
        ("strings-utf16le", ["strings", "-a", "-el", "-n", "8", str(path)], export_prefix.with_suffix(".strings-utf16le.txt"), 120),
    ]
    results = {}
    for key, cmd, out_path, timeout in commands:
        rc = run_to_file(cmd, out_path, timeout=timeout)
        logs[key] = out_path.relative_to(ROOT).as_posix()
        results[key] = rc

    # capa and FLOSS are intentionally opt-in for this project. They can take
    # tens of minutes on larger C++ DLLs and are not needed for the first pass.

    strings_hits = summarize_text(export_prefix.with_suffix(".strings-ascii.txt"), [
        "yandex", "speech", "speechkit", "passport", "alice", "update", "service", "policy",
        "http://", "https://", ".pdb", "BuildAgent", "build_root", "TeamCity",
    ])
    die_hits = summarize_text(log_prefix.with_suffix(".diec.txt"), ["packer", "protector", "upx", "compiler", "microsoft", "visual c++"])

    return {
        "schema": "active_pe_static_triage",
        "schema_version": 1,
        "artifact": rel,
        "artifact_sha256": sha256(path),
        "collected_at_utc": utc_now(),
        "extractor": "openyandex-static-pe-triage",
        "extractor_version": "python3-v1",
        "command": ".workflows/tools/static-pe-triage.py " + name,
        "confidence": 0.9,
        "data": {
            "name": name,
            "size": path.stat().st_size,
            "logs": logs,
            "returncodes": results,
            "string_hit_categories": strings_hits,
            "die_hit_categories": die_hits,
            "heavy_tools_skipped": ["capa", "floss"],
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", nargs="*", choices=sorted(TARGETS.keys()) + ["all"], default=["all"])
    args = parser.parse_args()
    names = sorted(TARGETS) if "all" in args.targets else args.targets
    LOGS.mkdir(parents=True, exist_ok=True)
    EXPORTS.mkdir(parents=True, exist_ok=True)
    META.mkdir(parents=True, exist_ok=True)

    rows = []
    for name in names:
        path = TARGETS[name]
        if not path.exists():
            raise SystemExit(f"missing target: {path}")
        print(f"triage {name}")
        rows.append(triage(name, path))

    with OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    print(OUT.relative_to(ROOT))


if __name__ == "__main__":
    main()
