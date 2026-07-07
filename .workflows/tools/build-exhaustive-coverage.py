#!/usr/bin/env python3
"""Build an explicit coverage gate for exhaustive change mapping."""

import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".workflows" / "metadata"
ACTIVE = ROOT / ".workflows" / "active-stage"
OUT = META / "exhaustive-change-coverage.jsonl"
TXT = ACTIVE / "exhaustive-change-coverage.txt"

BASELINE_BINARY_PRESENT = True
BASELINE_BINARY_EXACT = False
BINDIFF_TOOL_PRESENT = False

SUBAGENT_COVERED = {
    "network_yandex_headers": "metadata_mapped",
    "enterprise_policy_and_prefs": "metadata_mapped",
    "telemetry_metrics_abt": "metadata_mapped",
    "gost_crypto_security": "metadata_low_evidence",
    "ui_branding_ntp_smartbox": "metadata_mapped",
    "ai_alice_speechkit_yagpt": "metadata_mapped",
    "privacy_antitracking_adblock": "metadata_mapped",
    "dlp_clipboard_drag_download_watermark": "metadata_mapped",
    "device_posture_browser_enforcement": "metadata_mapped",
    "passport_yandex_id_account": "metadata_mapped",
    "widgets_flutter_bubbles": "metadata_mapped",
    "updater_service_onboarding": "metadata_mapped",
    "textclassifier_ocr_cv": "metadata_mapped",
    "media_video_engine": "defer_mapped",
    "gpu_angle_swiftshader_runtime": "drop_mapped",
    "crash_wer_internals": "defer_mapped",
}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path):
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def main():
    patch_rows = read_jsonl(META / "patch-map-v1.jsonl")
    rows = []
    for row in patch_rows:
        d = row["data"]
        fam = d["family"]
        coverage = SUBAGENT_COVERED.get(fam, "seed_only")
        blockers = []
        if not BASELINE_BINARY_PRESENT:
            blockers.append("missing_chromium_windows_baseline_binary")
        elif not BASELINE_BINARY_EXACT:
            blockers.append("baseline_is_approximate_chrome_for_testing_136.0.7103.113_not_exact_136.0.7103.156")
        if not BINDIFF_TOOL_PRESENT:
            blockers.append("missing_bindiff_or_diaphora_cli")
        if coverage == "metadata_low_evidence":
            blockers.append("needs_direct_binary_or_string_evidence")
        exhaustive_state = "blocked_not_exhaustive"
        if d["decision"] == "drop" and coverage == "drop_mapped":
            exhaustive_state = "drop_mapped_but_not_bindiff_exhaustive"
        elif d["decision"] == "defer" and coverage == "defer_mapped":
            exhaustive_state = "defer_mapped_but_not_bindiff_exhaustive"
        rows.append({
            "schema": "exhaustive_change_coverage",
            "schema_version": 1,
            "artifact": None,
            "artifact_sha256": None,
            "collected_at_utc": now(),
            "extractor": "openyandex-exhaustive-coverage-builder",
            "extractor_version": "python3-v1",
            "command": ".workflows/tools/build-exhaustive-coverage.py",
            "confidence": 0.9,
            "data": {
                "family": fam,
                "priority": d["priority"],
                "decision": d["decision"],
                "patch_map_status": d["status"],
                "metadata_coverage": coverage,
                "exhaustive_state": exhaustive_state,
                "baseline_binary_present": BASELINE_BINARY_PRESENT,
                "baseline_binary_exact": BASELINE_BINARY_EXACT,
                "bindiff_tool_present": BINDIFF_TOOL_PRESENT,
                "blockers": blockers,
                "required_to_close": [
                    "matching_chromium_windows_baseline_binary",
                    "function_level_bindiff_or_equivalent",
                    "diff_chunks_assigned_to_patch_map_family",
                    "terminal_status_for_every_diff_chunk",
                ],
            },
        })

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    lines = ["Exhaustive Change Coverage", ""]
    lines.append("Verdict: blocked_not_exhaustive")
    lines.append("Reason: only approximate Chrome-for-Testing 136.0.7103.113 win32 baseline is present; exact 136.0.7103.156 baseline and BinDiff/Diaphora CLI are still missing.")
    lines.append("")
    for row in rows:
        d = row["data"]
        lines.append(f"{d['priority']} {d['family']} decision={d['decision']} coverage={d['metadata_coverage']} state={d['exhaustive_state']}")
        if d["blockers"]:
            lines.append(f"- blockers: {', '.join(d['blockers'])}")
    lines.append("")
    lines.append("Do not claim all changes are documented until every row reaches a terminal non-blocked state and every BinDiff chunk is assigned.")
    TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUT.relative_to(ROOT))
    print(TXT.relative_to(ROOT))


if __name__ == "__main__":
    main()
