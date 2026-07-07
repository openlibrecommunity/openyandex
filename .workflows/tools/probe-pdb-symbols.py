#!/usr/bin/env python3
"""Probe selected PDB symbol URLs with HEAD and tiny ranged GET."""

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".workflows" / "metadata"
OUT = META / "active-pdb-probes.jsonl"

TARGETS = [
    ("browser.dll.pdb", "5881CBC31AEA815B4C4C44205044422E1"),
    ("browser.exe.pdb", "667BC9756C38438F4C4C44205044422E1"),
    ("Yandex.exe.pdb", "9E5DBA162D5AA0864C4C44205044422E1"),
    ("Alice.exe.pdb", "138E34ABFB6460A84C4C44205044422E1"),
    ("browser_elf.dll.pdb", "F7F4A9CB2574C5854C4C44205044422E1"),
    ("browser_wer.dll.pdb", "7124DA22C3C5282D4C4C44205044422E1"),
    ("service_update.exe.pdb", "E42043EDF87584334C4C44205044422E1"),
]

BASES = [
    "https://debug-symbols.browser.yandex.net",
    "https://debug-symbols.browser.yandex.ru",
    "https://browser-symbols.yandex.net",
    "https://browser-symbols.yandex.ru",
    "https://symbols.yandex.net",
    "https://symbols.yandex.ru",
    "https://chromium-browser-symsrv.commondatastorage.googleapis.com",
    "https://msdl.microsoft.com/download/symbols",
]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def curl_probe(url):
    head = subprocess.run(
        ["curl", "--location", "--head", "--silent", "--show-error", "--max-time", "12", "--write-out", "%{http_code} %{size_download} %{url_effective}", "--output", "/dev/null", url],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
        check=False,
    )
    ranged = subprocess.run(
        ["curl", "--location", "--range", "0-7", "--silent", "--show-error", "--max-time", "12", "--write-out", "\n%{http_code} %{size_download}", url],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    body, _, trailer = ranged.stdout.partition(b"\n")
    return {
        "head_returncode": head.returncode,
        "head_stdout": head.stdout.strip(),
        "head_stderr": head.stderr.strip()[:500],
        "range_returncode": ranged.returncode,
        "range_status": trailer.decode("utf-8", errors="replace").strip(),
        "range_first_hex": body[:8].hex(),
        "range_stderr": ranged.stderr.decode("utf-8", errors="replace").strip()[:500],
    }


def main():
    rows = []
    for pdb, guidage in TARGETS:
        for base in BASES:
            for suffix in (pdb, pdb + ".pd_"):
                url = f"{base}/{pdb}/{guidage}/{suffix}"
                print(url)
                rows.append({
                    "schema": "active_pdb_symbol_probe",
                    "schema_version": 1,
                    "artifact": None,
                    "artifact_sha256": None,
                    "collected_at_utc": now(),
                    "extractor": "openyandex-pdb-symbol-probe",
                    "extractor_version": "python3-v1",
                    "command": ".workflows/tools/probe-pdb-symbols.py",
                    "confidence": 0.7,
                    "data": {
                        "pdb": pdb,
                        "guidage": guidage,
                        "url": url,
                        "probe": curl_probe(url),
                    },
                })
    with OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    print(OUT.relative_to(ROOT))


if __name__ == "__main__":
    main()
