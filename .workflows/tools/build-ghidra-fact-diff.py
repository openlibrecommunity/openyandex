#!/usr/bin/env python3
"""Build an approximate fact-level diff from exported Ghidra JSONL facts."""

import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ACTIVE = ROOT / ".workflows" / "active-stage"
EXPORTS = ACTIVE / "exports"
META = ROOT / ".workflows" / "metadata"
BASE = EXPORTS / "chrome_136_7103_113_win32.ghidra-facts.jsonl"
YANDEX = EXPORTS / "yandex_browser_dll.ghidra-facts.jsonl"
OUT = META / "approx-ghidra-fact-diff.jsonl"
TXT = ACTIVE / "approx-ghidra-fact-diff.txt"

Y_TERMS = [
    "yandex", "alice", "passport", "speech", "speechkit", "neuro", "yagpt", "abt",
    "antitracking", "adblock", "deviceposture", "browserenforcement", "clipboard",
    "downloadrestrictions", "noreferer", "extcorp", "customheader", "gost", "cryptopro",
]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_facts(path):
    funcs = {}
    symbols = Counter()
    y_hits = []
    total = 0
    for line in path.open("r", encoding="utf-8"):
        if not line.strip():
            continue
        total += 1
        row = json.loads(line)
        data = row.get("data", {})
        schema = row.get("schema")
        name = data.get("name", "")
        lname = name.lower()
        if schema == "ghidra_function":
            funcs[name] = data
        if schema == "ghidra_symbol":
            symbols[data.get("type", "unknown")] += 1
        if name and any(term in lname for term in Y_TERMS):
            if len(y_hits) < 2000:
                y_hits.append({"schema": schema, "name": name, "address": data.get("address") or data.get("entry"), "type": data.get("type")})
    return {"total": total, "functions": funcs, "symbol_types": symbols, "y_hits": y_hits}


def main():
    base = read_facts(BASE)
    yandex = read_facts(YANDEX)
    base_names = set(base["functions"])
    y_names = set(yandex["functions"])
    common = base_names & y_names
    y_only = sorted(y_names - base_names)
    b_only = sorted(base_names - y_names)

    rows = []
    summary = {
        "schema": "approx_ghidra_fact_diff_summary",
        "schema_version": 1,
        "artifact": None,
        "artifact_sha256": None,
        "collected_at_utc": now(),
        "extractor": "openyandex-ghidra-fact-diff",
        "extractor_version": "python3-v1",
        "command": ".workflows/tools/build-ghidra-fact-diff.py",
        "confidence": 0.45,
        "data": {
            "warning": "approximate name/fact diff only; not BinDiff and not exact baseline",
            "baseline": str(BASE.relative_to(ROOT)),
            "yandex": str(YANDEX.relative_to(ROOT)),
            "baseline_fact_rows": base["total"],
            "yandex_fact_rows": yandex["total"],
            "baseline_functions": len(base_names),
            "yandex_functions": len(y_names),
            "common_function_names": len(common),
            "yandex_only_function_names": len(y_only),
            "baseline_only_function_names": len(b_only),
            "baseline_symbol_types": dict(base["symbol_types"]),
            "yandex_symbol_types": dict(yandex["symbol_types"]),
            "yandex_named_hits_count_sampled": len(yandex["y_hits"]),
        },
    }
    rows.append(summary)

    for name in y_only[:20000]:
        data = yandex["functions"][name]
        rows.append({
            "schema": "approx_yandex_only_function_name",
            "schema_version": 1,
            "artifact": None,
            "artifact_sha256": None,
            "collected_at_utc": now(),
            "extractor": "openyandex-ghidra-fact-diff",
            "extractor_version": "python3-v1",
            "command": ".workflows/tools/build-ghidra-fact-diff.py",
            "confidence": 0.35,
            "data": data,
        })
    for hit in yandex["y_hits"]:
        rows.append({
            "schema": "approx_yandex_named_symbol_hit",
            "schema_version": 1,
            "artifact": None,
            "artifact_sha256": None,
            "collected_at_utc": now(),
            "extractor": "openyandex-ghidra-fact-diff",
            "extractor_version": "python3-v1",
            "command": ".workflows/tools/build-ghidra-fact-diff.py",
            "confidence": 0.55,
            "data": hit,
        })

    META.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    lines = ["Approximate Ghidra Fact Diff", ""]
    lines.append("WARNING: not BinDiff; baseline is approximate 136.0.7103.113, target is 136.0.7103.156.")
    for k, v in summary["data"].items():
        lines.append(f"- {k}: {v}")
    lines.append("")
    lines.append("Sample Yandex named hits")
    for hit in yandex["y_hits"][:80]:
        lines.append(f"- {hit.get('schema')} {hit.get('address')} {hit.get('type')} {hit.get('name')}")
    TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUT.relative_to(ROOT))
    print(TXT.relative_to(ROOT))


if __name__ == "__main__":
    main()
