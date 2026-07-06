#!/usr/bin/env python3
"""Build policy priority rows for RE triage."""

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".workflows" / "metadata"
OUT = META / "policy-priority.jsonl"


FAMILY_KEYWORDS = {
    "clipboard_dlp": ["clipboard", "copy", "paste"],
    "download_restrictions": ["downloadrestriction", "download_restriction"],
    "cloud_management": ["cloudenrollment", "cmurl", "cloud_management"],
    "network_privacy": ["noreferer", "no_referer", "customheader"],
    "watermark_dlp": ["watermark"],
    "drag_drop_dlp": ["drag", "drop"],
    "file_upload_dlp": ["defaultupload", "uploadallowed", "uploadblocked", "upload_allowed", "upload_blocked"],
    "page_save_dlp": ["defaultpagesave", "pagesave", "page_save"],
    "smartbox_search": ["smartbox", "search"],
    "content_filtering": ["contentfilter", "content_filter"],
    "browser_update": ["backgroundupdate", "background_update"],
    "yandex_services": ["passport", "alice", "zen", "kinopoisk", "speechkit", "smartbox"],
}


def read_jsonl(path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def exact_variants_for(name):
    parts = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name).lower()
    parts = re.sub(r"[^a-z0-9]+", " ", parts).split()
    return sorted({name.lower(), "".join(parts), "_".join(parts), "-".join(parts)})


def infer_family(policy_name, category, text):
    name_haystack = policy_name.lower()
    name_compact = re.sub(r"[^a-z0-9]+", "", name_haystack)
    haystack = f"{policy_name} {category or ''} {text or ''}".lower()
    matched = []

    if any(key in name_compact for key in ("clipboard", "copy", "paste")):
        matched.append("clipboard_dlp")
    if "downloadrestrictions" in name_compact:
        matched.append("download_restrictions")
    if any(key in name_compact for key in ("cloudenrollment", "cmurl", "cloudmanagement")):
        matched.append("cloud_management")
    if any(key in name_compact for key in ("noreferer", "customheader", "antitracking")):
        matched.append("network_privacy")
    if "watermark" in name_compact:
        matched.append("watermark_dlp")
    if any(key in name_compact for key in ("disableinformationdrag", "disableinformationdrop")):
        matched.append("drag_drop_dlp")
    if any(key in name_compact for key in ("defaultupload", "uploadallowed", "uploadblocked")):
        matched.append("file_upload_dlp")
    if any(key in name_compact for key in ("defaultpagesave", "pagesaveallowed", "pagesaveblocked")):
        matched.append("page_save_dlp")
    if any(key in name_compact for key in ("smartbox", "searchprovider")):
        matched.append("smartbox_search")
    if "contentfilter" in name_compact:
        matched.append("content_filtering")
    if "backgroundupdate" in name_compact:
        matched.append("browser_update")
    if name_haystack.startswith(("yandex", "ya")):
        if "yandex_services" not in matched:
            matched.append("yandex_services")
    if any(key in haystack for key in ("passport", "alice", "zen", "kinopoisk", "speechkit")):
        if "yandex_services" not in matched:
            matched.append("yandex_services")
    return matched or ["unclassified"]


def is_generic_policy_name(name):
    return len(name) < 14 and not name.lower().startswith(("yandex", "ya"))


def load_crossrefs():
    rows = {}
    path = META / "yandex-policy-crossrefs.jsonl"
    if not path.exists():
        return rows
    for row in read_jsonl(path):
        data = row.get("data", {})
        name = data.get("policy_name")
        if name:
            rows[name] = data
    return rows


def load_string_hits(policy_names):
    tokens = {name: exact_variants_for(name) for name in policy_names if not is_generic_policy_name(name)}
    hits = defaultdict(list)
    for row in read_jsonl(META / "yandex-strings.jsonl"):
        data = row.get("data", {})
        value = data.get("value", "")
        if not value:
            continue
        lower = value.lower()
        for name, variants in tokens.items():
            if any(v and v in lower for v in variants):
                bucket = hits[name]
                if len(bucket) < 12:
                    bucket.append({
                        "artifact": data.get("source_relative_path"),
                        "encoding": data.get("encoding"),
                        "offset": data.get("offset"),
                        "value": value[:300],
                    })
                break
    return hits


def load_path_hints(policy_names):
    policy_rows = {}
    for row in read_jsonl(META / "yandex-policy-classification.jsonl"):
        data = row.get("data", {})
        name = data.get("name")
        if name in policy_names:
            src = data.get("source_policy", {})
            text = "\n".join(filter(None, [src.get("displayName_en"), src.get("explainText_en")]))
            families = infer_family(name, data.get("category"), text)
            policy_rows[name] = families
    family_tokens = {
        name: sorted({key for family in policy_rows.get(name, []) for key in FAMILY_KEYWORDS.get(family, []) if key not in {"yandex", "ya"}})
        for name in policy_names
    }
    hints = defaultdict(list)
    for row in read_jsonl(META / "yandex-source-paths.jsonl"):
        data = row.get("data", {})
        path = data.get("normalized_path", "")
        if not path:
            continue
        lower = path.lower()
        top = data.get("top_component") or ""
        if top == "third_party" and "yandex" not in lower:
            continue
        for name, variants in family_tokens.items():
            if variants and any(v and v in lower for v in variants):
                bucket = hints[name]
                if len(bucket) < 12:
                    bucket.append({
                        "artifact": data.get("source_relative_path"),
                        "path": path,
                        "offset": data.get("offset"),
                        "top_component": data.get("top_component"),
                    })
                break
    return hints


def score_policy(data, crossref, string_hits, path_hints):
    score = 0
    classification = data.get("classification")
    if classification == "yandex_only":
        score += 100
    elif classification == "not_in_chromium_admx":
        score += 80
    else:
        score += 10

    families = set(data.get("families", []))
    if families & {"clipboard_dlp", "download_restrictions", "watermark_dlp", "drag_drop_dlp", "file_upload_dlp", "page_save_dlp"}:
        score += 30
    if families & {"cloud_management", "network_privacy", "content_filtering"}:
        score += 25
    if string_hits:
        score += min(40, 8 * len(string_hits))
    if path_hints:
        score += min(30, 10 * len(path_hints))
    if crossref.get("yandex_string_hits"):
        score += min(30, 6 * len(crossref.get("yandex_string_hits", [])))
    if crossref.get("chromium_evidence_hits") and classification != "chromium_inherited":
        score += 10
    return score


def main():
    classifications = []
    for row in read_jsonl(META / "yandex-policy-classification.jsonl"):
        data = row.get("data", {})
        if data.get("classification") == "chromium_inherited":
            continue
        classifications.append(data)

    names = [row["name"] for row in classifications]
    crossrefs = load_crossrefs()
    string_hits = load_string_hits(names)
    path_hints = load_path_hints(names)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    out_rows = []
    for data in classifications:
        name = data["name"]
        src = data.get("source_policy", {})
        text = "\n".join(filter(None, [src.get("displayName_en"), src.get("explainText_en")]))
        families = infer_family(name, data.get("category"), text)
        data = dict(data)
        data["families"] = families
        crossref = crossrefs.get(name, {})
        row_string_hits = string_hits.get(name, [])
        row_path_hints = path_hints.get(name, [])
        priority = score_policy(data, crossref, row_string_hits, row_path_hints)
        out_rows.append({
            "schema": "policy_priority",
            "schema_version": 1,
            "artifact": ".workflows/metadata/yandex-policy-classification.jsonl",
            "artifact_sha256": None,
            "extractor": "openyandex-policy-priority-builder",
            "extractor_version": "python3-v1",
            "command": ".workflows/tools/build-policy-priority.py",
            "collected_at_utc": now,
            "confidence": 0.85,
            "data": {
                "policy_name": name,
                "base_name": data.get("base_name"),
                "classification": data.get("classification"),
                "category": data.get("category"),
                "families": families,
                "priority_score": priority,
                "registry_key": data.get("registry_key"),
                "value_name": src.get("valueName"),
                "displayName_en": src.get("displayName_en"),
                "summary_en": (src.get("explainText_en") or "").split("\n\n", 1)[0],
                "crossref_status": crossref.get("status"),
                "string_hits_count": len(row_string_hits) + len(crossref.get("yandex_string_hits", [])),
                "source_path_hints_count": len(row_path_hints),
                "chromium_evidence_count": len(crossref.get("chromium_evidence_hits", [])) + len(crossref.get("chromium_exact_name_hits", [])),
                "string_hits": row_string_hits[:8],
                "source_path_hints": row_path_hints[:8],
                "chromium_evidence": (crossref.get("chromium_evidence_hits", []) + crossref.get("chromium_exact_name_hits", []))[:8],
            },
        })

    out_rows.sort(key=lambda row: (-row["data"]["priority_score"], row["data"]["policy_name"]))
    with OUT.open("w", encoding="utf-8") as f:
        for row in out_rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    counts = Counter(row["data"]["classification"] for row in out_rows)
    print(f"wrote {OUT.relative_to(ROOT)}")
    print(f"rows {len(out_rows)}")
    for key, value in sorted(counts.items()):
        print(f"{key} {value}")
    print("top")
    for row in out_rows[:10]:
        data = row["data"]
        print(f"{data['priority_score']} {data['classification']} {data['policy_name']} {','.join(data['families'])}")


if __name__ == "__main__":
    main()
