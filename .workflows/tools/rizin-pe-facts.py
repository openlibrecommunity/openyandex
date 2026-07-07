#!/usr/bin/env python3
"""Export rizin/rabin2 facts for PE files."""

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".workflows" / "metadata"
OUT = META / "rizin-pe-facts.jsonl"

TARGETS = {
    "baseline_chrome_dll": ROOT / "artifacts" / "binaries" / "chrome-for-testing-136.0.7103.113-win32" / "chrome-win32" / "chrome.dll",
    "yandex_browser_dll": ROOT / "artifacts" / "binaries" / "yandex-browser-25.6.0.2372" / "payload" / "Browser-bin" / "25.6.0.2372" / "browser.dll",
}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_json(cmd):
    proc = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300, check=False)
    if proc.returncode != 0 or not proc.stdout.strip():
        return {"returncode": proc.returncode, "stderr": proc.stderr[:1000], "data": None}
    try:
        return {"returncode": proc.returncode, "stderr": proc.stderr[:1000], "data": json.loads(proc.stdout)}
    except json.JSONDecodeError:
        return {"returncode": proc.returncode, "stderr": proc.stderr[:1000], "data": proc.stdout[:2000]}


def main():
    rows = []
    for name, path in TARGETS.items():
        facts = {
            "info": run_json(["rabin2", "-Ij", str(path)]),
            "imports": run_json(["rabin2", "-ij", str(path)]),
            "exports": run_json(["rabin2", "-Ej", str(path)]),
            "sections": run_json(["rabin2", "-Sj", str(path)]),
            "strings": run_json(["rabin2", "-zj", str(path)]),
        }
        rows.append({
            "schema": "rizin_pe_facts",
            "schema_version": 1,
            "artifact": path.relative_to(ROOT).as_posix(),
            "artifact_sha256": None,
            "collected_at_utc": now(),
            "extractor": "openyandex-rizin-pe-facts",
            "extractor_version": "python3-v1",
            "command": ".workflows/tools/rizin-pe-facts.py",
            "confidence": 0.9,
            "data": {"target": name, "facts": facts},
        })
    META.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    print(OUT.relative_to(ROOT))


if __name__ == "__main__":
    main()
