#!/usr/bin/env python3
"""Build terminal-ish mapped chunk statuses from review and xref evidence.

This does not claim final exhaustive closure. It records current terminal
decisions for implementation planning, while preserving blockers such as the
non-exact Chrome baseline and chunks that still need xref/caller proof.
"""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".workflows" / "metadata"
ACTIVE = ROOT / ".workflows" / "active-stage"
OUT = META / "mapped-chunks-v1.jsonl"
TXT = ACTIVE / "mapped-chunks-v1.txt"


DROP_OR_DEFER = {
    "rizin-imports-media_video_engine": ("defer_vendor_runtime", "Media Foundation/D3D9/DXVA imports are runtime/media plumbing; keep only if later tied to visible Yandex feature."),
    "source-path-cluster-media_video_engine": ("defer_vendor_runtime", "ANGLE D3D9/libGLES source paths are vendor runtime evidence, not a Yandex product feature by themselves."),
    "rizin-imports-crash_wer_internals": ("drop_or_defer_crash_internals", "browser_elf crash/WER internals are not user-visible unless tied to telemetry policy behavior."),
    "source-path-cluster-textclassifier_ocr_cv": ("drop_misassigned", "This source-path chunk is Zoho web-app launcher image evidence, not textclassifier/OCR/CV evidence; textclassifier module evidence remains separate and still needs caller proof."),
}


MANUAL_PROMOTIONS = {
    "rizin-imports-updater_service_onboarding": ("mapped_keep_candidate_requires_xref", "Service, WinHTTP/WinINet, installer/updater imports match visible updater/onboarding family; caller-level proof still required."),
    "source-path-cluster-updater_service_onboarding": ("mapped_keep_candidate_split_required", "Contains Yandex native_cache and updater/onboarding paths but also generic extension/policy updater paths; split before implementation."),
    "rizin-imports-device_posture_browser_enforcement": ("mapped_keep_candidate_requires_xref", "User/device/SID/interface imports support device posture and browser enforcement; source-path cluster already confirms family."),
    "rizin-imports-passport_yandex_id_account": ("mapped_keep_candidate_requires_xref", "Credential Manager and UUID imports support Passport/Yandex ID account storage; source-path cluster confirms OAuth delegate."),
    "rizin-imports-gost_crypto_security": ("mapped_keep_candidate_requires_xref", "CryptoAPI/CERT imports support GOST/certificate handling; noisy source-path cluster needs GOST-specific split and xrefs."),
    "source-path-cluster-gost_crypto_security": ("mapped_keep_candidate_split_required", "Contains generic SSL/certificate paths plus likely GOST/CryptoPro anchors; split to product-relevant crypto changes before implementation."),
    "rizin-imports-enterprise_policy_and_prefs": ("mapped_keep_candidate_requires_xref", "Registry/NT key imports support enterprise policy and pref plumbing; source-path cluster confirms policy family."),
    "rizin-imports-ui_branding_ntp_smartbox": ("mapped_keep_candidate_split_required", "UI/resource/accessibility imports align with visible UI work but need split into branding/NTP/smartbox subchunks."),
    "source-path-cluster-ui_branding_ntp_smartbox": ("mapped_keep_candidate_split_required", "Large visible UI/Yandex images cluster; split out unrelated Skia/resource noise before implementation."),
    "rizin-imports-dlp_clipboard_drag_download_watermark": ("mapped_keep_candidate_xref_seen", "CopyFileEx pairs with DLP/download copy flows; clipboard xref and drag/drop source path give partial support."),
    "rizin-imports-telemetry_metrics_abt": ("mapped_keep_candidate_requires_xref", "Crashpad/eventlog/power/process metrics imports support telemetry/ABT, but caller proof is still required."),
    "rizin-imports-unknown": ("split_required", "Generic OS/browser_elf imports need rebucketing; do not implement as one family."),
}


IMPLEMENTATION_STATUS = {
    "mapped_keep_xref_backed_candidate": "mapped_keep_candidate",
    "mapped_keep_candidate_xref_seen": "mapped_keep_candidate",
    "mapped_keep_candidate_symbol_seen": "mapped_keep_candidate_requires_xref",
}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.open("r", encoding="utf-8") if line.strip()]


def xref_summary(rows):
    out = {}
    for row in rows:
        d = row["data"]
        out[d["chunk_id"]] = {
            "xref_promotion_status": d["promotion_status"],
            "xref_hits": d.get("xref_hits", 0),
            "symbol_hits": d.get("symbol_hits", 0),
        }
    return out


def raw_network_summary(rows):
    counts = Counter()
    samples = {}
    for row in rows:
        if row.get("schema") != "raw_pe_offset_xref":
            continue
        d = row["data"]
        label = d.get("label")
        counts[label] += 1
        samples.setdefault(label, []).append({k: d.get(k) for k in ("ref_kind", "ref_file_offset", "ref_va", "function", "function_entry")})
    return {label: {"raw_offset_xrefs": count, "samples": samples.get(label, [])[:10]} for label, count in counts.items()}


def caller_summary(rows):
    out = {}
    for row in rows:
        d = row["data"]
        out[d["chunk_id"]] = {
            "import_matched_terms": d.get("matched_terms", 0),
            "import_caller_functions": d.get("caller_functions", 0),
            "import_caller_terms": [
                {
                    "term": term.get("term"),
                    "caller_count": len(term.get("functions", [])),
                    "sample_functions": term.get("functions", [])[:5],
                }
                for term in d.get("terms", [])[:20]
            ],
        }
    return out


def unknown_split_summary(rows):
    if not rows:
        return None
    statuses = Counter(row["data"]["status"] for row in rows)
    return {
        "split_count": len(rows),
        "status_counts": dict(sorted(statuses.items())),
        "splits": [
            {
                "split_id": row["data"]["split_id"],
                "status": row["data"]["status"],
                "import_count": row["data"]["import_count"],
            }
            for row in rows
        ],
    }


def source_split_summary(rows):
    by_parent = {}
    grouped = {}
    for row in rows:
        d = row["data"]
        grouped.setdefault(d["parent_chunk_id"], []).append(d)
    for parent, splits in grouped.items():
        statuses = Counter(split["status"] for split in splits)
        by_parent[parent] = {
            "split_count": len(splits),
            "status_counts": dict(sorted(statuses.items())),
            "splits": [
                {
                    "split_id": split["split_id"],
                    "status": split["status"],
                    "evidence_count": split["evidence_count"],
                }
                for split in splits
            ],
        }
    return by_parent


def row_for(review, xrefs, raw_network, callers, unknown_split, source_splits):
    d = review["data"]
    chunk_id = d["chunk_id"]
    status = d["review_status"]
    rationale = d["rationale"]
    blockers = []
    evidence = {
        "review_status": status,
        "review_confidence_label": d["confidence_label"],
        "review_evidence_count": d["evidence_count"],
    }

    if chunk_id in DROP_OR_DEFER:
        status, rationale = DROP_OR_DEFER[chunk_id]
    elif chunk_id in MANUAL_PROMOTIONS:
        status, rationale = MANUAL_PROMOTIONS[chunk_id]

    if chunk_id in xrefs:
        evidence.update(xrefs[chunk_id])
        promoted = IMPLEMENTATION_STATUS.get(xrefs[chunk_id]["xref_promotion_status"])
        if promoted and status.startswith("mapped_keep_candidate"):
            status = promoted

    if chunk_id in callers:
        evidence["import_caller_evidence"] = callers[chunk_id]
        if chunk_id == "rizin-imports-telemetry_metrics_abt" and callers[chunk_id]["import_caller_functions"] > 0:
            status = "mapped_keep_candidate_call_seen"
            rationale = "Crashpad/upload consent imports have caller-level function evidence; remaining work is mapping telemetry behavior, not proving the import is live."

    network_label_by_chunk = {
        "browser-seed-network-mojom-networkservice-setyandexcustomheader": "set_yandex_custom_header",
        "browser-seed-yandexcustomheader": "set_yandex_custom_header",
        "browser-seed-network-mojom-networkservice-setyandexnoreferersettingallowlist": "set_yandex_no_referer_setting_allowlist",
        "browser-seed-yandexnoreferersettingallowlist": "set_yandex_no_referer_setting_allowlist",
        "browser-seed-network-mojom-networkservice-setyandexextcorpbrowserheader": "set_yandex_ext_corp_browser_header",
        "browser-seed-yandexextcorpbrowserheader": "set_yandex_ext_corp_browser_header",
    }
    label = network_label_by_chunk.get(chunk_id)
    if label and label in raw_network:
        evidence["raw_offset_reference"] = raw_network[label]
        if raw_network[label]["raw_offset_xrefs"] > 0:
            status = "mapped_keep_candidate_raw_xref_seen"

    if chunk_id == "rizin-imports-unknown" and unknown_split:
        evidence["unknown_import_split"] = unknown_split
        status = "split_resolved_defer_or_drop"
        rationale = "Residual unknown imports were split into baseline-equivalent, OS-integration, and runtime-plumbing buckets; none are implementation-ready product features."

    if chunk_id in source_splits:
        evidence["source_cluster_splits"] = source_splits[chunk_id]

    if status in {"mapped_keep_candidate_requires_xref", "needs_caller_proof"}:
        blockers.append("caller_or_xref_proof_required")
    if status in {"mapped_keep_candidate_split_required", "split_required"}:
        blockers.append("split_required_before_implementation")

    return {
        "schema": "mapped_chunk_v1",
        "schema_version": 1,
        "artifact": None,
        "artifact_sha256": None,
        "collected_at_utc": now(),
        "extractor": "openyandex-mapped-chunks-builder",
        "extractor_version": "python3-v1",
        "command": ".workflows/tools/build-mapped-chunks-v1.py",
        "confidence": 0.78,
        "data": {
            "chunk_id": chunk_id,
            "assigned_family": d["assigned_family"],
            "kind": d["kind"],
            "mapped_status": status,
            "rationale": rationale,
            "blockers": blockers,
            "evidence": evidence,
        },
    }


def main():
    reviews = read_jsonl(META / "chunk-review-v1.jsonl")
    xrefs = xref_summary(read_jsonl(META / "xref-promotion-v1.jsonl"))
    raw_network = raw_network_summary(read_jsonl(META / "raw-network-string-xrefs-v1.jsonl"))
    callers = caller_summary(read_jsonl(META / "import-caller-evidence-v1.jsonl"))
    unknown_split = unknown_split_summary(read_jsonl(META / "unknown-import-split-v1.jsonl"))
    source_splits = source_split_summary(read_jsonl(META / "source-cluster-splits-v1.jsonl"))
    rows = [row_for(review, xrefs, raw_network, callers, unknown_split, source_splits) for review in reviews]

    with OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    counts = Counter(row["data"]["mapped_status"] for row in rows)
    families = Counter(row["data"]["assigned_family"] for row in rows if row["data"]["mapped_status"].startswith("mapped_keep"))
    lines = ["Mapped Chunks v1", "", "Status counts:"]
    for key, value in sorted(counts.items()):
        lines.append(f"- {key}: {value}")
    lines.extend(["", "Keep-candidate families:"])
    for key, value in sorted(families.items()):
        lines.append(f"- {key}: {value}")
    lines.extend(["", "Chunks:"])
    for row in rows:
        d = row["data"]
        blocker = f" blockers={','.join(d['blockers'])}" if d["blockers"] else ""
        lines.append(f"{d['chunk_id']} | {d['assigned_family']} | {d['mapped_status']}{blocker}")
        lines.append(f"- {d['rationale']}")
    TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUT.relative_to(ROOT))
    print(TXT.relative_to(ROOT))


if __name__ == "__main__":
    main()
