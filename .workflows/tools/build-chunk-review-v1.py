#!/usr/bin/env python3
"""Review and promote first diff chunks using subagent conclusions."""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".workflows" / "metadata"
ACTIVE = ROOT / ".workflows" / "active-stage"
OUT = META / "chunk-review-v1.jsonl"
TXT = ACTIVE / "chunk-review-v1.txt"


PROMOTIONS = {
    "rizin-imports-ai_alice_speechkit_yagpt": ("mapped_keep_candidate", "high", "Direct Yandex browser.dll imports from cspeechkit.dll and Dart runtime; confirmed by Ghidra/rizin and source-path cluster."),
    "source-path-cluster-ai_alice_speechkit_yagpt": ("mapped_keep_candidate", "medium-high", "Strong C++ source-path subset for SpeechKit, neuro question, neuroedit, speech recognition, and Alice renderer/UI surfaces."),
    "browser-seed-network-mojom-networkservice-setyandexcustomheader": ("mapped_keep_candidate", "high", "Direct browser.dll NetworkService mojom method string with policy evidence."),
    "browser-seed-network-mojom-networkservice-setyandexnoreferersettingallowlist": ("mapped_keep_candidate", "high", "Direct browser.dll NetworkService mojom method string for no-referer allowlist with ADMX policy evidence."),
    "browser-seed-network-mojom-networkservice-setyandexextcorpbrowserheader": ("mapped_keep_candidate", "high", "Direct browser.dll NetworkService mojom method string for enterprise header with ADMX policy evidence."),
    "browser-seed-yandexcustomheader": ("mapped_keep_candidate_alias", "high", "Policy/plumbing alias of SetYandexCustomHeader."),
    "browser-seed-yandexnoreferersettingallowlist": ("mapped_keep_candidate_alias", "high", "Policy/plumbing alias of SetYandexNoRefererSettingAllowlist."),
    "browser-seed-yandexextcorpbrowserheader": ("mapped_keep_candidate_alias", "high", "Policy/plumbing alias of SetYandexExtCorpBrowserHeader."),
    "rizin-yandex-only-exports": ("mapped_keep_candidate", "high", "Yandex browser.dll exports full FlutterEngine embedder surface absent from Chrome baseline."),
    "source-path-cluster-widgets_flutter_bubbles": ("mapped_keep_candidate", "medium-high", "Flutter embedder/runtime/source paths in browser.dll plus widget ELF AOT snapshots."),
    "browser-seed-yandex-common-drag-and-drop-js": ("mapped_keep_candidate", "high", "Direct Yandex drag/drop JS source-path anchor for DLP."),
    "source-path-cluster-dlp_clipboard_drag_download_watermark": ("mapped_keep_candidate", "medium", "DLP source-path cluster; requires pruning but contains drag/drop and enterprise DLP anchors."),
    "source-path-cluster-device_posture_browser_enforcement": ("mapped_keep_candidate", "high", "Clean source-path cluster for Yandex corporate device posture and browser enforcement services/state."),
    "source-path-cluster-enterprise_policy_and_prefs": ("mapped_keep_candidate", "high", "Policy infrastructure and Yandex corporate policy/prefs source-path cluster; foundational for other families."),
    "source-path-cluster-passport_yandex_id_account": ("mapped_keep_candidate", "high", "Passport OAuth2 token service delegate and Yandex signin/sync/account source paths."),
    "source-path-cluster-telemetry_metrics_abt": ("mapped_keep_candidate", "medium-high", "ABT/metrics/variations source-path cluster, dedicated abt-bindings evidence."),
    "rizin-imports-telemetry_metrics_abt": ("mapped_keep_candidate_requires_xref", "medium", "Crashpad metrics export thunk; needs caller xref."),
}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path):
    return [json.loads(line) for line in path.open("r", encoding="utf-8") if line.strip()]


def main():
    rows = []
    for chunk in read_jsonl(META / "diff-chunks-v1.jsonl"):
        d = chunk["data"]
        status, confidence_label, rationale = PROMOTIONS.get(
            d["chunk_id"],
            ("assigned_needs_review" if d["assigned_family"] != "unknown" else "needs_manual_assignment", "medium", "No promotion decision yet."),
        )
        rows.append({
            "schema": "chunk_review_v1",
            "schema_version": 1,
            "artifact": None,
            "artifact_sha256": None,
            "collected_at_utc": now(),
            "extractor": "openyandex-chunk-review-builder",
            "extractor_version": "python3-v1",
            "command": ".workflows/tools/build-chunk-review-v1.py",
            "confidence": 0.8,
            "data": {
                "chunk_id": d["chunk_id"],
                "kind": d["kind"],
                "assigned_family": d["assigned_family"],
                "review_status": status,
                "confidence_label": confidence_label,
                "rationale": rationale,
                "evidence_count": len(d.get("evidence", [])),
                "next_action": "targeted_xrefs" if "candidate" in status else "manual_bucket_or_review",
            },
        })
    with OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    counts = Counter(row["data"]["review_status"] for row in rows)
    lines = ["Chunk Review v1", ""]
    for key, value in sorted(counts.items()):
        lines.append(f"- {key}: {value}")
    lines.append("")
    for row in rows:
        d = row["data"]
        lines.append(f"{d['chunk_id']} | {d['assigned_family']} | {d['review_status']} | {d['confidence_label']} | evidence={d['evidence_count']}")
        lines.append(f"- {d['rationale']}")
    TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUT.relative_to(ROOT))
    print(TXT.relative_to(ROOT))


if __name__ == "__main__":
    main()
