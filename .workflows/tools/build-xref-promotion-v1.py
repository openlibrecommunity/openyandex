#!/usr/bin/env python3
"""Summarize targeted Ghidra xrefs and promote validated chunks."""

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXPORTS = ROOT / ".workflows" / "active-stage" / "exports"
META = ROOT / ".workflows" / "metadata"
ACTIVE = ROOT / ".workflows" / "active-stage"
XREFS = EXPORTS / "yandex_browser_dll.targeted-xrefs.jsonl"
OUT = META / "xref-promotion-v1.jsonl"
TXT = ACTIVE / "xref-promotion-v1.txt"


TERM_TO_CHUNKS = {
    "ysk_setapikey": ["rizin-imports-ai_alice_speechkit_yagpt"],
    "ysk_setuuid": ["rizin-imports-ai_alice_speechkit_yagpt"],
    "ysk_setplatforminfo": ["rizin-imports-ai_alice_speechkit_yagpt"],
    "yskvoicedialogsettings": ["rizin-imports-ai_alice_speechkit_yagpt"],
    "yskrecognizersettings": ["rizin-imports-ai_alice_speechkit_yagpt"],
    "yskphrasespottersettings": ["rizin-imports-ai_alice_speechkit_yagpt"],
    "yskrecognition_getbestresulttext": ["rizin-imports-ai_alice_speechkit_yagpt"],
    "setyandexcustomheader": ["browser-seed-network-mojom-networkservice-setyandexcustomheader", "browser-seed-yandexcustomheader"],
    "setyandexnoreferersettingallowlist": ["browser-seed-network-mojom-networkservice-setyandexnoreferersettingallowlist", "browser-seed-yandexnoreferersettingallowlist"],
    "setyandexextcorpbrowserheader": ["browser-seed-network-mojom-networkservice-setyandexextcorpbrowserheader", "browser-seed-yandexextcorpbrowserheader"],
    "flutterenginecreateaotdata": ["rizin-yandex-only-exports", "source-path-cluster-widgets_flutter_bubbles"],
    "flutterenginerun": ["rizin-yandex-only-exports", "source-path-cluster-widgets_flutter_bubbles"],
    "flutterenginesendplatformmessage": ["rizin-yandex-only-exports", "source-path-cluster-widgets_flutter_bubbles"],
    "flutterengineinitialize": ["rizin-yandex-only-exports", "source-path-cluster-widgets_flutter_bubbles"],
    "flutterengineshutdown": ["rizin-yandex-only-exports", "source-path-cluster-widgets_flutter_bubbles"],
    "addclipboardformatlistener": ["browser-seed-yandex-common-drag-and-drop-js", "source-path-cluster-dlp_clipboard_drag_download_watermark"],
    "configurebrowserenforcement": ["source-path-cluster-device_posture_browser_enforcement"],
    "textclassifier": ["source-path-cluster-textclassifier_ocr_cv"],
    "ncvlib_createtextclassifier": ["source-path-cluster-textclassifier_ocr_cv"],
    "ncvlib_classifyimagewithtextclassifer": ["source-path-cluster-textclassifier_ocr_cv"],
}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.open("r", encoding="utf-8") if line.strip()]


def main():
    xrefs = read_jsonl(XREFS)
    terms = defaultdict(lambda: {"symbols": 0, "xrefs": 0, "functions": Counter(), "samples": []})
    for row in xrefs:
        d = row["data"]
        term = d.get("term", "")
        if row["schema"] == "target_symbol_hit":
            terms[term]["symbols"] += 1
        elif row["schema"] == "target_xref":
            terms[term]["xrefs"] += 1
            if d.get("function"):
                terms[term]["functions"][d["function"]] += 1
            if len(terms[term]["samples"]) < 20:
                terms[term]["samples"].append(d)

    chunk_evidence = defaultdict(list)
    for term, info in terms.items():
        for chunk in TERM_TO_CHUNKS.get(term, []):
            chunk_evidence[chunk].append({"term": term, "symbols": info["symbols"], "xrefs": info["xrefs"], "top_functions": info["functions"].most_common(10), "samples": info["samples"]})

    rows = []
    for chunk, evidence in sorted(chunk_evidence.items()):
        total_xrefs = sum(e["xrefs"] for e in evidence)
        total_symbols = sum(e["symbols"] for e in evidence)
        status = "mapped_keep_candidate_xref_seen" if total_xrefs else "mapped_keep_candidate_symbol_seen"
        if total_xrefs >= 3:
            status = "mapped_keep_xref_backed_candidate"
        rows.append({
            "schema": "xref_promotion_v1",
            "schema_version": 1,
            "artifact": None,
            "artifact_sha256": None,
            "collected_at_utc": now(),
            "extractor": "openyandex-xref-promotion-builder",
            "extractor_version": "python3-v1",
            "command": ".workflows/tools/build-xref-promotion-v1.py",
            "confidence": 0.75,
            "data": {"chunk_id": chunk, "promotion_status": status, "symbol_hits": total_symbols, "xref_hits": total_xrefs, "term_evidence": evidence},
        })

    with OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    lines = ["Xref Promotion v1", ""]
    for row in rows:
        d = row["data"]
        lines.append(f"{d['chunk_id']} | {d['promotion_status']} | symbols={d['symbol_hits']} | xrefs={d['xref_hits']}")
        for ev in d["term_evidence"]:
            lines.append(f"- {ev['term']}: symbols={ev['symbols']} xrefs={ev['xrefs']} top={ev['top_functions'][:5]}")
    TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUT.relative_to(ROOT))
    print(TXT.relative_to(ROOT))


if __name__ == "__main__":
    main()
