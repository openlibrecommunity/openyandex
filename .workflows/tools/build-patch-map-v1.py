#!/usr/bin/env python3
"""Build initial patch-map families for full-fork reconstruction."""

import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".workflows" / "metadata"
ACTIVE = ROOT / ".workflows" / "active-stage"
OUT = META / "patch-map-v1.jsonl"
TXT = ACTIVE / "patch-map-v1.txt"
BACKLOG = ACTIVE / "subagent-backlog.txt"


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ev(kind, value, artifact=None, offset=None, confidence="medium"):
    data = {"kind": kind, "value": value, "confidence": confidence}
    if artifact:
        data["artifact"] = artifact
    if offset is not None:
        data["offset"] = offset
    return data


def family(name, priority, decision, user_visible, mode, areas, yandex_areas, evidence, slices, notes, blockers=None, status="seed"):
    return {
        "schema": "patch_map_family",
        "schema_version": 1,
        "artifact": None,
        "artifact_sha256": None,
        "collected_at_utc": now(),
        "extractor": "openyandex-patch-map-builder",
        "extractor_version": "python3-v1",
        "command": ".workflows/tools/build-patch-map-v1.py",
        "confidence": 0.75,
        "data": {
            "family": name,
            "priority": priority,
            "decision": decision,
            "user_visible": user_visible,
            "implementation_mode": mode,
            "status": status,
            "target_chromium_areas": areas,
            "yandex_areas": yandex_areas,
            "evidence": evidence,
            "subagent_slices": slices,
            "implementation_notes": notes,
            "blockers": blockers or [],
        },
    }


def rows():
    browser = "artifacts/binaries/yandex-browser-25.6.0.2372/payload/Browser-bin/25.6.0.2372/browser.dll"
    return [
        family(
            "network_yandex_headers",
            "P0",
            "keep",
            True,
            "direct_chromium_edit",
            ["services/network", "services/network/public/mojom", "net", "chrome/browser/policy"],
            ["net/yandex", "services/yandex"],
            [
                ev("browser_string", "network::mojom::NetworkService::SetYandexCustomHeader", browser, 198821101, "high"),
                ev("browser_string", "network::mojom::NetworkService::SetYandexNoRefererSettingAllowlist", browser, 198821407, "high"),
                ev("browser_string", "network::mojom::NetworkService::SetYandexExtCorpBrowserHeader", browser, 198821282, "high"),
                ev("policy", "YandexCustomHeader / YandexNoRefererSettingAllowlist / YandexExtCorpBrowserHeader", ".workflows/metadata/policy-priority.jsonl", None, "high"),
            ],
            ["Map NetworkService mojom additions", "Map policy-to-network propagation", "Find Chromium NetworkService insertion points"],
            "Implement Yandex request header/no-referer controls in network service and policy plumbing.",
        ),
        family(
            "enterprise_policy_and_prefs",
            "P0",
            "keep",
            True,
            "direct_chromium_edit",
            ["chrome/browser/policy", "components/policy", "chrome/common/pref_names*", "tools/metrics/histograms"],
            ["components/yandex", "chrome/browser/yandex"],
            [ev("policy", "428 Yandex ADMX policies; 98 Yandex-only; 77 not in exact Chromium ADMX", ".workflows/metadata/yandex-policy-classification.jsonl", None, "high")],
            ["Classify policy handlers", "Map prefs and registry values", "Separate inherited vs Yandex-only"],
            "Create full Yandex policy/pref layer before feature implementations consume it.",
        ),
        family(
            "telemetry_metrics_abt",
            "P0",
            "keep",
            True,
            "direct_chromium_edit",
            ["components/metrics", "chrome/browser/metrics", "components/variations", "chrome/browser/enterprise"],
            ["browser/experiments/abt", "components/yandex"],
            [ev("pdb", "abt-bindings.pdb / browser/experiments/abt/bindings/dynamic", ".workflows/metadata/yandex-pdb-index.jsonl", None, "high"), ev("strings", "ABT/experiments/Yandex strings corpus", ".workflows/metadata/yandex-strings.jsonl", None, "medium")],
            ["Map ABT bindings", "Map metric/event names", "Decide telemetry endpoints and privacy surface"],
            "User-visible through tracking/experiments/product behavior; build after policy/network base.",
        ),
        family(
            "gost_crypto_security",
            "P0",
            "keep",
            True,
            "direct_chromium_edit",
            ["net/cert", "net/ssl", "crypto", "components/security_interstitials", "chrome/browser/ssl"],
            ["net/yandex", "components/yandex"],
            [ev("scope", "GOST/security explicitly in keep scope", "notes/re/project-goal-full-fork.txt", None, "medium")],
            ["Search GOST/cert strings", "Map TLS/cert verification hooks", "Identify policy controls"],
            "Needs dedicated evidence collection; likely high product/compliance value.",
            ["Evidence not yet mapped; needs BinDiff/string pass."],
        ),
        family(
            "ui_branding_ntp_smartbox",
            "P0",
            "keep",
            True,
            "direct_chromium_edit",
            ["chrome/browser/ui", "chrome/browser/ui/views", "chrome/browser/resources", "components/omnibox", "chrome/browser/search"],
            ["chrome/browser/ui/views/yandex", "ntp", "ui_config", "web_app_config"],
            [ev("source_path", "chrome/browser/ui/views/yandex/*", ".workflows/metadata/yandex-source-paths.jsonl", None, "high"), ev("resource", "ntp/ui_config/web_app_config payload directories", "artifacts/binaries/yandex-browser-25.6.0.2372/payload", None, "high")],
            ["NTP resource map", "Smartbox/omnibox diffs", "Views/yandex source-path clusters", "Branding resources"],
            "Large visible UI workstream; split into NTP, smartbox, settings, toolbar, bubbles.",
        ),
        family(
            "ai_alice_speechkit_yagpt",
            "P0",
            "keep",
            True,
            "direct_chromium_edit",
            ["chrome/browser", "components", "services", "ui/views"],
            ["speechkit", "Alice.exe", "cspeechkit.dll", "speechkit_action_lib.dll", "widgets/neuro*"],
            [ev("ghidra", "speechkit_action_lib.dll analyzed; exports ActionLibInitialize/ExecuteDirective/ProcessDirective", ".workflows/active-stage/exports/speechkit_action_lib.ghidra-facts.jsonl", None, "high"), ev("pe", "cspeechkit.dll exports 356 YSK* symbols", ".workflows/metadata/active-pe-triage.jsonl", None, "high"), ev("widget", "neuroedit/neuro_question widgets", ".workflows/metadata/active-widget-elf-triage.jsonl", None, "high")],
            ["Reverse speechkit_action_lib exports", "Map cspeechkit C API", "Cluster neuro widget endpoints", "Find browser integration points"],
            "High user-visible AI surface; start from speechkit_action_lib Ghidra project and widgets.",
        ),
        family(
            "privacy_antitracking_adblock",
            "P0",
            "keep",
            True,
            "direct_chromium_edit",
            ["components/content_settings", "chrome/browser/subresource_filter", "services/network", "extensions", "chrome/browser/privacy"],
            ["components/yandex", "chrome/browser/yandex"],
            [ev("policy", "YandexAntiTracking top policy seed", ".workflows/metadata/policy-priority.jsonl", None, "high"), ev("policy", "YandexAdblock top policy seed", ".workflows/metadata/policy-priority.jsonl", None, "high")],
            ["Map policies to enforcement", "Find rule resource files", "Compare to Chromium subresource_filter"],
            "Core visible privacy/tracking behavior; depends on policy and network base.",
        ),
        family(
            "dlp_clipboard_drag_download_watermark",
            "P0",
            "keep",
            True,
            "direct_chromium_edit",
            ["chrome/browser/download", "content/browser", "chrome/browser/ui", "components/policy", "ui/base/clipboard"],
            ["components/yandex", "yandex/common/drag_and_drop.js"],
            [ev("policy", "YandexClipboardAccessByPolicyEnabled and download restrictions", ".workflows/metadata/policy-priority.jsonl", None, "high"), ev("source_path", "yandex/common/drag_and_drop.js", browser, 201598530, "high")],
            ["Clipboard policy handlers", "Download URL/type restrictions", "Drag/drop JS integration", "Watermark settings"],
            "Enterprise/user-visible controls; implement after policy base.",
        ),
        family(
            "device_posture_browser_enforcement",
            "P0",
            "keep",
            True,
            "direct_chromium_edit",
            ["chrome/browser/enterprise", "components/enterprise", "services/network", "components/policy"],
            ["components/yandex", "chrome/browser/yandex"],
            [ev("policy", "YandexDevicePosture / YandexDevicePostureRules", ".workflows/metadata/policy-priority.jsonl", None, "high"), ev("policy", "YandexBrowserEnforcement and X-Ybe-* headers", ".workflows/metadata/yandex-policies.jsonl", None, "medium")],
            ["Map posture rule format", "Map enforcement headers", "Find enterprise controller hooks"],
            "Corporate enforcement/user blocking surface; likely tied to network_yandex_headers.",
        ),
        family(
            "passport_yandex_id_account",
            "P1",
            "keep",
            True,
            "direct_chromium_edit",
            ["chrome/browser/signin", "components/signin", "chrome/browser/profiles", "chrome/browser/sync"],
            ["PassportO2TS", "Yandex ID", "components/yandex"],
            [ev("strings", "PassportO2TS/Yandex ID strings observed in corpus", ".workflows/metadata/yandex-strings.jsonl", None, "medium")],
            ["Map account strings", "Find signin/profile hooks", "Separate sync vs passport UX"],
            "User-visible identity layer; needs more evidence before implementation plan.",
        ),
        family(
            "widgets_flutter_bubbles",
            "P1",
            "keep",
            True,
            "binary_module_bridge",
            ["chrome/browser/ui/views", "chrome/browser/resources", "components"],
            ["widgets/*.so", "libdart_precompiled_runtime_product.dll"],
            [ev("elf", "First five widgets triaged; Dart/Flutter strings", ".workflows/metadata/active-widget-elf-triage.jsonl", None, "high")],
            ["Cluster all widget strings", "Map embedder/loader", "Decide native reimplementation vs bridge"],
            "Visible UI bubbles; likely use binary bridge or reimplementation depending on loader complexity.",
        ),
        family(
            "updater_service_onboarding",
            "P1",
            "keep",
            True,
            "direct_chromium_edit",
            ["chrome/updater", "chrome/browser/first_run", "chrome/installer", "chrome/browser/ui"],
            ["service_update.exe", "Browser-bin/service_update.exe"],
            [ev("pe", "service_update.exe imports WINHTTP/WININET/WINTRUST/CRYPT32", ".workflows/metadata/active-pe-triage.jsonl", None, "medium")],
            ["Separate updater service from visible onboarding", "Map first-run/update UI", "Decide service implementation scope"],
            "Keep visible/update behavior, defer low-level service internals if not product-critical.",
        ),
        family(
            "textclassifier_ocr_cv",
            "P1",
            "keep",
            True,
            "binary_module_bridge",
            ["components", "services", "chrome/browser/ui"],
            ["textclassifier.dll", "cv/imageproc/ocr"],
            [ev("pe", "textclassifier.dll has 2336 OpenCV-style exports and OCR path", ".workflows/metadata/active-pe-triage.jsonl", None, "high")],
            ["Map exported API", "Find browser callers", "Decide bridge vs reimplementation"],
            "Keep if tied to user-visible OCR/AI/text actions.",
        ),
        family(
            "media_video_engine",
            "P3",
            "defer",
            False,
            "research_only",
            ["media", "third_party/ffmpeg"],
            ["ffmpeg-plugin-yandex-browser"],
            [ev("package", "Linux ffmpeg debuginfo exists", ".workflows/metadata/linux-debug-symbols.jsonl", None, "medium")],
            ["Only map if tied to visible kept feature", "Do not spend active cycle here first"],
            "Explicitly low priority unless tied to AI/video translation or product-visible media behavior.",
        ),
        family(
            "gpu_angle_swiftshader_runtime",
            "P3",
            "drop",
            False,
            "drop",
            ["gpu", "third_party/angle", "third_party/swiftshader"],
            ["libEGL.dll", "libGLESv2.dll", "vk_swiftshader.dll", "vulkan-1.dll"],
            [ev("artifact", "Bundled GPU/runtime DLLs present", ".workflows/active-stage/artifact-map.txt", None, "medium")],
            ["Ignore unless BinDiff proves kept feature dependency"],
            "Pure bundled runtime differences are out of initial product fork scope.",
            status="dropped",
        ),
        family(
            "crash_wer_internals",
            "P3",
            "defer",
            False,
            "research_only",
            ["chrome/browser/crash_upload", "components/crash", "base"],
            ["browser_wer.dll", "eventlog_provider.dll"],
            [ev("pdb", "browser_wer.dll.pdb and eventlog_provider.dll.pdb identities known", ".workflows/metadata/yandex-pdb-index.jsonl", None, "medium")],
            ["Only keep telemetry-visible crash reporting pieces", "Drop Windows WER internals if not needed"],
            "Defer unless telemetry/product behavior requires it.",
        ),
    ]


def main():
    META.mkdir(parents=True, exist_ok=True)
    ACTIVE.mkdir(parents=True, exist_ok=True)
    data = rows()
    with OUT.open("w", encoding="utf-8") as f:
        for row in data:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    lines = ["Patch Map v1", ""]
    for row in data:
        d = row["data"]
        lines.append(f"{d['priority']} {d['decision']} {d['family']} status={d['status']} user_visible={d['user_visible']}")
        lines.append(f"- mode: {d['implementation_mode']}")
        lines.append(f"- chromium: {', '.join(d['target_chromium_areas'])}")
        lines.append(f"- yandex: {', '.join(d['yandex_areas'])}")
        lines.append(f"- next: {'; '.join(d['subagent_slices'])}")
        lines.append("")
    TXT.write_text("\n".join(lines), encoding="utf-8")

    backlog = ["Subagent Backlog", ""]
    for row in data:
        d = row["data"]
        if d["decision"] == "drop":
            continue
        backlog.append(f"{d['family']} ({d['priority']}, {d['decision']})")
        for item in d["subagent_slices"]:
            backlog.append(f"- {item}")
        backlog.append("")
    BACKLOG.write_text("\n".join(backlog), encoding="utf-8")

    print(OUT.relative_to(ROOT))
    print(TXT.relative_to(ROOT))
    print(BACKLOG.relative_to(ROOT))


if __name__ == "__main__":
    main()
