#!/usr/bin/env python3
"""Record baseline Chrome-for-Testing metadata for diff preparation."""

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "artifacts" / "binaries" / "chrome-for-testing-136.0.7103.113-win32" / "chrome-win32"
META = ROOT / ".workflows" / "metadata"
OUT = META / "baseline-chrome-win32.jsonl"


FILES = ["chrome.dll", "chrome.exe", "chrome_elf.dll", "chrome_wer.dll"]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd):
    proc = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120, check=False)
    return proc.stdout.strip()[:4000]


def main():
    rows = []
    for name in FILES:
        path = BASE / name
        rows.append({
            "schema": "baseline_chrome_win32_file",
            "schema_version": 1,
            "artifact": path.relative_to(ROOT).as_posix(),
            "artifact_sha256": sha256(path),
            "collected_at_utc": now(),
            "extractor": "openyandex-baseline-metadata",
            "extractor_version": "python3-v1",
            "command": ".workflows/tools/build-baseline-metadata.py",
            "confidence": 0.9,
            "data": {
                "name": name,
                "version": "136.0.7103.113",
                "platform": "win32",
                "source": "Chrome for Testing",
                "url": "https://storage.googleapis.com/chrome-for-testing-public/136.0.7103.113/win32/chrome-win32.zip",
                "exact_target_match": False,
                "target_version": "136.0.7103.156",
                "target_commit": "465616851cd99c308e1ce42d0fd818c04c094830",
                "target_commit_position": "refs/branch-heads/7103@{#2840}",
                "size": path.stat().st_size,
                "file": run(["file", str(path)]),
                "codeview": run(["llvm-readobj", "--codeview", str(path)]),
            },
        })

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    print(OUT.relative_to(ROOT))


if __name__ == "__main__":
    main()
