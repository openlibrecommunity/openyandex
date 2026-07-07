#!/usr/bin/env python3
"""Build custom Ghidra+rizin diff summary."""

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ACTIVE = ROOT / ".workflows" / "active-stage"
EXPORTS = ACTIVE / "exports"
META = ROOT / ".workflows" / "metadata"
BASE_FUNCS = EXPORTS / "chrome_136_7103_113_win32.function-diff-facts.jsonl"
YANDEX_FUNCS = EXPORTS / "yandex_browser_dll.function-diff-facts.jsonl"
RIZIN = META / "rizin-pe-facts.jsonl"
OUT = META / "ghidra-rizin-diff-summary.jsonl"
TXT = ACTIVE / "ghidra-rizin-diff-summary.txt"

Y_TERMS = ["Yandex", "YSK", "Speech", "Alice", "Passport", "Dart", "Flutter", "Clipboard", "CSPEECHKIT", "LIBDART", "browser_elf"]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_func_facts(path):
    rows = []
    by_hash = defaultdict(list)
    external_counter = Counter()
    interesting = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            data = row["data"]
            rows.append(data)
            if data.get("instruction_count", 0) >= 5:
                key = (data.get("mnemonic_hash"), data.get("instruction_count"), data.get("body_size"))
                by_hash[key].append(data)
            for ref in data.get("external_refs", []):
                external_counter[ref] += 1
                if any(term.lower() in ref.lower() for term in Y_TERMS):
                    interesting.append({"function": data.get("name"), "entry": data.get("entry"), "external_ref": ref})
    return {"rows": rows, "by_hash": by_hash, "externals": external_counter, "interesting": interesting}


def read_rizin():
    out = {}
    if not RIZIN.exists():
        return out
    for line in RIZIN.open("r", encoding="utf-8"):
        if line.strip():
            row = json.loads(line)
            out[row["data"]["target"]] = row["data"]["facts"]
    return out


def main():
    base = read_func_facts(BASE_FUNCS)
    yandex = read_func_facts(YANDEX_FUNCS)
    rizin = read_rizin()

    exact_hash_matches = 0
    yandex_unique_hash_rows = []
    base_hashes = set(base["by_hash"])
    for key, funcs in yandex["by_hash"].items():
        if key in base_hashes:
            exact_hash_matches += len(funcs)
        else:
            for f in funcs[:3]:
                if len(yandex_unique_hash_rows) < 20000:
                    yandex_unique_hash_rows.append(f)

    y_ext = set(yandex["externals"])
    b_ext = set(base["externals"])
    y_only_ext = sorted(y_ext - b_ext)
    interesting_ext = [x for x in y_only_ext if any(term.lower() in x.lower() for term in Y_TERMS)]

    summary = {
        "schema": "ghidra_rizin_diff_summary",
        "schema_version": 1,
        "artifact": None,
        "artifact_sha256": None,
        "collected_at_utc": now(),
        "extractor": "openyandex-ghidra-rizin-diff",
        "extractor_version": "python3-v1",
        "command": ".workflows/tools/build-ghidra-rizin-diff.py",
        "confidence": 0.6,
        "data": {
            "warning": "custom Ghidra+rizin diff; not exact baseline; analysis was partial due Ghidra timeout",
            "baseline_function_facts": len(base["rows"]),
            "yandex_function_facts": len(yandex["rows"]),
            "exact_mnemonic_size_hash_matches": exact_hash_matches,
            "yandex_unique_hash_sample_count": len(yandex_unique_hash_rows),
            "baseline_external_refs": len(b_ext),
            "yandex_external_refs": len(y_ext),
            "yandex_only_external_refs": len(y_only_ext),
            "interesting_yandex_only_external_refs": interesting_ext[:200],
            "interesting_external_ref_edges_sample": yandex["interesting"][:500],
            "rizin_targets": sorted(rizin),
        },
    }

    rows = [summary]
    for ref in interesting_ext[:1000]:
        rows.append({"schema": "ghidra_rizin_yandex_only_external_ref", "schema_version": 1, "artifact": None, "artifact_sha256": None, "collected_at_utc": now(), "extractor": "openyandex-ghidra-rizin-diff", "extractor_version": "python3-v1", "command": ".workflows/tools/build-ghidra-rizin-diff.py", "confidence": 0.7, "data": {"external_ref": ref, "count": yandex["externals"][ref]}})
    for f in yandex_unique_hash_rows[:2000]:
        rows.append({"schema": "ghidra_rizin_yandex_unique_function_hash_sample", "schema_version": 1, "artifact": None, "artifact_sha256": None, "collected_at_utc": now(), "extractor": "openyandex-ghidra-rizin-diff", "extractor_version": "python3-v1", "command": ".workflows/tools/build-ghidra-rizin-diff.py", "confidence": 0.45, "data": f})

    with OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    lines = ["Ghidra+rizin Diff Summary", ""]
    for k, v in summary["data"].items():
        if isinstance(v, list):
            lines.append(f"- {k}: {len(v)} items")
        else:
            lines.append(f"- {k}: {v}")
    lines.append("")
    lines.append("Interesting Yandex-only external refs")
    for ref in interesting_ext[:120]:
        lines.append(f"- {ref}: {yandex['externals'][ref]}")
    TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUT.relative_to(ROOT))
    print(TXT.relative_to(ROOT))


if __name__ == "__main__":
    main()
