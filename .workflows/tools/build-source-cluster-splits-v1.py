#!/usr/bin/env python3
"""Split noisy source-path clusters into implementation-oriented subclusters."""

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".workflows" / "metadata"
ACTIVE = ROOT / ".workflows" / "active-stage"
OUT = META / "source-cluster-splits-v1.jsonl"
TXT = ACTIVE / "source-cluster-splits-v1.txt"


SPLIT_RULES = {
    "source-path-cluster-ui_branding_ntp_smartbox": [
        ("yandex_id_assets", "mapped_keep_candidate", ["yandex/images/yandex_id", "yandex_id"], "Yandex ID/profile menu assets are visible UI/product work."),
        ("ntp_webapp_resources", "mapped_keep_candidate", ["/ntp", "ntp/", "new_tab", "web_ntp", "ntp_"], "NTP resource paths are visible UI work."),
        ("smartbox_omnibox", "mapped_keep_candidate", ["smartbox", "omnibox", "suggest"], "Smartbox/omnibox paths are visible search UI work."),
        ("yandex_views_native_ui", "mapped_keep_candidate", ["ui/views/yandex", "browser/ui/views/yandex", "views/yandex"], "Native Yandex Views paths are visible browser UI work."),
        ("toolbar_frame_bubbles", "mapped_keep_candidate", ["toolbar", "bubble", "frame", "caption", "tab_strip"], "Toolbar/frame/bubble paths are visible browser UI work."),
        ("settings_search_ui", "mapped_keep_candidate", ["settings", "search_engine", "search/"], "Settings/search UI paths are visible configuration work."),
        ("branding_assets", "mapped_keep_candidate", ["branding", "yandex/images", "/logo", "logo.", "icon."], "Branding/image assets are visible UI work."),
        ("third_party_rendering_noise", "defer_vendor_runtime", ["third_party/skia", "third_party/dawn", "third_party/ink"], "Rendering/vendor paths are not Yandex UI features by themselves."),
    ],
    "source-path-cluster-gost_crypto_security": [
        ("gost_tls_cert_verifier", "mapped_keep_candidate_requires_xref", ["gost", "tlsgost", "cryptopro", "cades"], "GOST/CryptoPro/TLS-GOST paths are product/security relevant but need caller/policy linkage."),
        ("certificate_verifier_generic", "defer_requires_gost_link", ["cert_verifier", "certificate", "cert_", "ocsp", "crl"], "Generic certificate verifier evidence only stays if tied to GOST-specific behavior."),
        ("ssl_tls_generic", "defer_vendor_runtime", ["boringssl", "/ssl/", "tls_", "dtls", "webrtc"], "Generic SSL/TLS/vendor paths are not Yandex-specific by themselves."),
        ("crypto_storage_generic", "defer_requires_gost_link", ["crypto", "encrypt", "random_bytes", "frame_crypto"], "Generic crypto/storage evidence only stays if tied to Yandex product behavior."),
    ],
    "source-path-cluster-updater_service_onboarding": [
        ("yandex_native_cache", "mapped_keep_candidate", ["components/yandex/native_cache", "native_cache"], "Yandex native cache update job affects visible web/NTP resource delivery."),
        ("visible_welcome_onboarding", "mapped_keep_candidate", ["welcome", "onboarding", "first_run", "intro"], "Welcome/onboarding paths are user-visible."),
        ("installer_yandex_service", "mapped_keep_candidate_requires_xref", ["chrome/installer/yandex", "installer/yandex", "service_update", "broupdater", "browser_update"], "Yandex installer/service update paths need caller/service linkage before implementation."),
        ("extension_component_updater_generic", "defer_component_runtime", ["extensions/browser/updater", "extension_updater", "component_cloud_policy_updater", "external_policy_data_updater", "update_service.cc"], "Generic extension/component updater paths are not Yandex product features by themselves."),
        ("css_color_update_noise", "defer_runtime_plumbing", ["colors_css_updater", "color_change_listener"], "Color/CSS updater plumbing is not updater/onboarding evidence by itself."),
    ],
    "source-path-cluster-textclassifier_ocr_cv": [
        ("zoho_webapp_launcher_images", "drop_misassigned", ["zohocrm", "launcher_images", "not_yandex"], "These are web app launcher image paths, not textclassifier/OCR/CV evidence."),
        ("textclassifier_ocr_cv", "needs_caller_proof", ["textclassifier", "ocr", "opencv", "ncvlib"], "Textclassifier/OCR paths would be kept only with browser caller proof."),
    ],
}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path):
    return [json.loads(line) for line in path.open("r", encoding="utf-8") if line.strip()]


def classify(chunk_id, value):
    lower = (value or "").lower()
    for split, status, keys, rationale in SPLIT_RULES[chunk_id]:
        if any(key in lower for key in keys):
            return split, status, rationale
    return "unmatched_noise", "needs_manual_review", "No subcluster rule matched."


def make_row(chunk_id, split_id, status, rationale, evidence):
    return {
        "schema": "source_cluster_split_v1",
        "schema_version": 1,
        "artifact": None,
        "artifact_sha256": None,
        "collected_at_utc": now(),
        "extractor": "openyandex-source-cluster-split-builder",
        "extractor_version": "python3-v1",
        "command": ".workflows/tools/build-source-cluster-splits-v1.py",
        "confidence": 0.73,
        "data": {
            "parent_chunk_id": chunk_id,
            "split_id": f"{chunk_id}-{split_id}",
            "status": status,
            "rationale": rationale,
            "evidence_count": len(evidence),
            "sample_evidence": evidence[:20],
        },
    }


def main():
    rows = []
    for row in read_jsonl(META / "diff-chunks-v1.jsonl"):
        d = row["data"]
        chunk_id = d.get("chunk_id")
        if chunk_id not in SPLIT_RULES:
            continue
        grouped = defaultdict(list)
        meta = {}
        for ev in d.get("evidence", []):
            value = ev.get("value") or ""
            split_id, status, rationale = classify(chunk_id, value)
            grouped[split_id].append(ev)
            meta[split_id] = (status, rationale)
        for split_id, evidence in sorted(grouped.items()):
            status, rationale = meta[split_id]
            rows.append(make_row(chunk_id, split_id, status, rationale, evidence))

    with OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    lines = ["Source Cluster Splits v1", ""]
    status_counts = Counter(row["data"]["status"] for row in rows)
    lines.append("Status counts:")
    for key, value in sorted(status_counts.items()):
        lines.append(f"- {key}: {value}")
    lines.append("")
    current_parent = None
    for row in rows:
        d = row["data"]
        if d["parent_chunk_id"] != current_parent:
            current_parent = d["parent_chunk_id"]
            lines.append(current_parent)
        lines.append(f"- {d['split_id']} | {d['status']} | evidence={d['evidence_count']}")
        lines.append(f"- {d['rationale']}")
        for ev in d["sample_evidence"][:5]:
            lines.append(f"- sample: {ev.get('value')}")
    TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUT.relative_to(ROOT))
    print(TXT.relative_to(ROOT))


if __name__ == "__main__":
    main()
