#!/usr/bin/env python3
"""Mine Ghidra function-diff facts for callers of Yandex-only imports."""

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".workflows" / "metadata"
ACTIVE = ROOT / ".workflows" / "active-stage"
FACTS = ACTIVE / "exports" / "yandex_browser_dll.function-diff-facts.jsonl"
OUT = META / "import-caller-evidence-v1.jsonl"
TXT = ACTIVE / "import-caller-evidence-v1.txt"


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.open("r", encoding="utf-8") if line.strip()]


def import_name(value):
    return value.rsplit("::", 1)[-1]


def normalize_term(name):
    lower = name.lower()
    lower = re.sub(r"^(delayload_|thunk_)", "", lower)
    return re.sub(r"[^a-z0-9_]+", "", lower)


def targets_from_chunks():
    targets = {}
    for row in read_jsonl(META / "diff-chunks-v1.jsonl"):
        d = row["data"]
        if d.get("kind") != "yandex_only_imports":
            continue
        chunk_id = d["chunk_id"]
        for ev in d.get("evidence", []):
            value = ev.get("value") or ""
            name = import_name(value)
            term = normalize_term(name)
            if len(term) < 5:
                continue
            targets.setdefault(term, {"chunks": set(), "symbols": set(), "name": name})
            targets[term]["chunks"].add(chunk_id)
            targets[term]["symbols"].add(value)
    return targets


def make_row(chunk_id, terms):
    total_callers = sum(len(info["functions"]) for info in terms.values())
    data = {
        "chunk_id": chunk_id,
        "matched_terms": len(terms),
        "caller_functions": total_callers,
        "terms": [],
    }
    for term, info in sorted(terms.items()):
        data["terms"].append({
            "term": term,
            "import_symbols": sorted(info["symbols"]),
            "functions": info["functions"][:20],
        })
    return {
        "schema": "import_caller_evidence_v1",
        "schema_version": 1,
        "artifact": None,
        "artifact_sha256": None,
        "collected_at_utc": now(),
        "extractor": "openyandex-import-caller-evidence-builder",
        "extractor_version": "python3-v1",
        "command": ".workflows/tools/build-import-caller-evidence-v1.py",
        "confidence": 0.72,
        "data": data,
    }


def main():
    targets = targets_from_chunks()
    chunk_terms = defaultdict(lambda: defaultdict(lambda: {"symbols": set(), "functions": []}))
    terms = list(targets.keys())

    with FACTS.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("schema") != "ghidra_function_diff_fact":
                continue
            d = row.get("data", {})
            symbols = d.get("called_symbols", []) + d.get("external_refs", [])
            if not symbols:
                continue
            normalized_symbols = [(sym, normalize_term(sym)) for sym in symbols]
            for term in terms:
                hit_symbols = [sym for sym, normalized in normalized_symbols if term and term in normalized]
                if not hit_symbols:
                    continue
                fn = {"function": d.get("name"), "function_entry": d.get("entry"), "matched_symbols": hit_symbols[:10]}
                for chunk_id in targets[term]["chunks"]:
                    info = chunk_terms[chunk_id][term]
                    info["symbols"].update(targets[term]["symbols"])
                    if len(info["functions"]) < 50:
                        info["functions"].append(fn)

    rows = [make_row(chunk_id, terms) for chunk_id, terms in sorted(chunk_terms.items())]
    with OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    lines = ["Import Caller Evidence v1", ""]
    counts = Counter()
    for row in rows:
        d = row["data"]
        counts[d["chunk_id"]] = d["caller_functions"]
    for chunk_id, count in counts.most_common():
        row = next(r for r in rows if r["data"]["chunk_id"] == chunk_id)
        d = row["data"]
        lines.append(f"{chunk_id} | matched_terms={d['matched_terms']} caller_functions={d['caller_functions']}")
        for term in d["terms"][:20]:
            funcs = ", ".join(f["function"] or f["function_entry"] or "" for f in term["functions"][:5])
            lines.append(f"- {term['term']}: callers={len(term['functions'])} sample={funcs}")
    TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUT.relative_to(ROOT))
    print(TXT.relative_to(ROOT))


if __name__ == "__main__":
    main()
