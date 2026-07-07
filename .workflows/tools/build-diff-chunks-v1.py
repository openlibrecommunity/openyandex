#!/usr/bin/env python3
"""Build first assignable diff chunks from Ghidra+rizin/static metadata."""

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".workflows" / "metadata"
ACTIVE = ROOT / ".workflows" / "active-stage"
OUT = META / "diff-chunks-v1.jsonl"
TXT = ACTIVE / "diff-chunks-v1.txt"


FAMILY_RULES = [
    ("ai_alice_speechkit_yagpt", ["cspeechkit", "speech", "speechkit", "alice", "yagpt", "neuro", "ysk", "libdart", "dart", "flutter"]),
    ("network_yandex_headers", ["setyandexcustomheader", "setyandexnoreferer", "setyandexextcorp", "customheader", "noreferer", "extcorp", "x-yandex", "x-ybe"]),
    ("enterprise_policy_and_prefs", ["policy", "policies", "admx", "pref", "configuration_policy"]),
    ("privacy_antitracking_adblock", ["antitracking", "adblock", "subresource_filter", "protectadblock"]),
    ("dlp_clipboard_drag_download_watermark", ["clipboard", "drag_and_drop", "downloadrestrictions", "watermark", "paste", "copy"]),
    ("device_posture_browser_enforcement", ["deviceposture", "browserenforcement", "browser_enforcement", "x-ybe", "posture"]),
    ("passport_yandex_id_account", ["passport", "yandex id", "yandex_id", "oauth", "xtoken", "signin", "signout"]),
    ("ui_branding_ntp_smartbox", ["smartbox", "ntp", "ui/views/yandex", "branding", "custo", "yandex/images"]),
    ("telemetry_metrics_abt", ["abt", "metrics", "variations", "experiment", "stickiness"]),
    ("gost_crypto_security", ["gost", "cryptopro", "cades", "ocsp", "crl", "certificate", "ssl", "tls"]),
    ("widgets_flutter_bubbles", ["widgets/", "_bubble.so", "flutter", "dart"]),
    ("updater_service_onboarding", ["service_update", "update", "updater", "background-update", "broupdater"]),
    ("textclassifier_ocr_cv", ["textclassifier", "opencv", "ocr", "cv::"]),
]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.open("r", encoding="utf-8") if line.strip()]


def assign_family(text):
    lower = text.lower()
    scores = []
    for family, keys in FAMILY_RULES:
        score = sum(1 for key in keys if key in lower)
        if score:
            scores.append((score, family))
    if not scores:
        return "unknown", 0
    scores.sort(reverse=True)
    return scores[0][1], scores[0][0]


def chunk(chunk_id, kind, title, evidence, confidence=0.7):
    text = title + "\n" + "\n".join(str(e.get("value", "")) for e in evidence)
    family, score = assign_family(text)
    return {
        "schema": "diff_chunk_v1",
        "schema_version": 1,
        "artifact": None,
        "artifact_sha256": None,
        "collected_at_utc": now(),
        "extractor": "openyandex-diff-chunk-builder",
        "extractor_version": "python3-v1",
        "command": ".workflows/tools/build-diff-chunks-v1.py",
        "confidence": confidence,
        "data": {
            "chunk_id": chunk_id,
            "kind": kind,
            "title": title,
            "assigned_family": family,
            "assignment_score": score,
            "status": "assigned" if family != "unknown" else "needs_manual_assignment",
            "evidence": evidence,
        },
    }


def rizin_chunks(rows):
    by_target = {row["data"]["target"]: row["data"]["facts"] for row in rows}
    base = by_target.get("baseline_chrome_dll", {})
    yandex = by_target.get("yandex_browser_dll", {})
    out = []

    def imports(facts):
        data = facts.get("imports", {}).get("data") or []
        if isinstance(data, dict):
            data = data.get("imports") or []
        vals = set()
        for item in data if isinstance(data, list) else []:
            lib = item.get("libname") or item.get("lib") or ""
            name = item.get("name") or ""
            if name:
                vals.add(f"{lib}::{name}" if lib else name)
        return vals

    def exports(facts):
        data = facts.get("exports", {}).get("data") or []
        if isinstance(data, dict):
            data = data.get("exports") or []
        vals = set()
        for item in data if isinstance(data, list) else []:
            name = item.get("name") or ""
            if name:
                vals.add(name)
        return vals

    y_only_imports = sorted(imports(yandex) - imports(base))
    y_only_exports = sorted(exports(yandex) - exports(base))
    buckets = defaultdict(list)
    for imp in y_only_imports:
        fam, _ = assign_family(imp)
        buckets[fam].append(imp)
    for fam, vals in buckets.items():
        out.append(chunk(f"rizin-imports-{fam}", "yandex_only_imports", f"Yandex-only imports: {fam}", [{"kind": "rizin_import", "value": v} for v in vals[:500]], 0.8))
    if y_only_exports:
        out.append(chunk("rizin-yandex-only-exports", "yandex_only_exports", "Yandex-only browser.dll exports", [{"kind": "rizin_export", "value": v} for v in y_only_exports[:500]], 0.75))
    return out


def seed_chunks():
    rows = read_jsonl(META / "browser-dll-seed-pack.jsonl")
    out = []
    for row in rows:
        d = row["data"]
        evidence = []
        for hit in d.get("browser_string_hits", []):
            evidence.append({"kind": "browser_string", "value": hit.get("value"), "offset": hit.get("offset")})
        for hit in d.get("browser_source_path_hits", []):
            evidence.append({"kind": "source_path", "value": hit.get("path"), "offset": hit.get("offset")})
        if evidence:
            safe = re.sub(r"[^a-zA-Z0-9]+", "-", d["term"]).strip("-").lower()[:80]
            out.append(chunk(f"browser-seed-{safe}", "browser_seed", d["term"], evidence, 0.85))
    return out


def source_path_chunks():
    rows = read_jsonl(META / "yandex-source-paths.jsonl")
    groups = defaultdict(list)
    for row in rows:
        data = row.get("data", {})
        path = data.get("normalized_path") or ""
        if not path:
            continue
        fam, score = assign_family(path)
        if fam != "unknown":
            groups[fam].append(data)
    out = []
    for fam, vals in groups.items():
        evidence = [{"kind": "source_path", "value": v.get("normalized_path"), "offset": v.get("offset"), "artifact": v.get("source_relative_path")} for v in vals[:300]]
        out.append(chunk(f"source-path-cluster-{fam}", "source_path_cluster", f"Source path cluster: {fam}", evidence, 0.75))
    return out


def main():
    chunks = []
    chunks.extend(rizin_chunks(read_jsonl(META / "rizin-pe-facts.jsonl")))
    chunks.extend(seed_chunks())
    chunks.extend(source_path_chunks())
    seen = set()
    deduped = []
    for row in chunks:
        cid = row["data"]["chunk_id"]
        if cid in seen:
            continue
        seen.add(cid)
        deduped.append(row)
    with OUT.open("w", encoding="utf-8") as f:
        for row in deduped:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    lines = ["Diff Chunks v1", ""]
    for row in deduped:
        d = row["data"]
        lines.append(f"{d['chunk_id']} | {d['kind']} | {d['assigned_family']} | evidence={len(d['evidence'])} | {d['title']}")
    TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUT.relative_to(ROOT))
    print(TXT.relative_to(ROOT))


if __name__ == "__main__":
    main()
