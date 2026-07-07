#!/usr/bin/env python3
"""Build a complete active-recon readiness pack from existing metadata."""

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".workflows" / "metadata"
ACTIVE = ROOT / ".workflows" / "active-stage"
OUT_TXT = ACTIVE / "active-ready-index.txt"
OUT_JSON = ACTIVE / "active-ready-index.json"
SEEDS_JSONL = META / "browser-dll-seed-pack.jsonl"
SEEDS_TXT = ACTIVE / "browser-dll-seed-pack.txt"


BROWSER_DLL = "Browser-bin/25.6.0.2372/browser.dll"

DIRECT_SEEDS = [
    "network::mojom::NetworkService::SetYandexCustomHeader",
    "network::mojom::NetworkService::SetYandexNoRefererSettingAllowlist",
    "network::mojom::NetworkService::SetYandexExtCorpBrowserHeader",
    "network::mojom::NetworkService::SetYandexAllowedDomainsForApps",
    "network::mojom::NetworkService::SetYandexLocaleHeader",
]

POLICY_SEEDS = [
    "YandexAntiTracking",
    "YandexAdblock",
    "YandexDevicePosture",
    "YandexDevicePostureRules",
    "YandexBrowserEnforcement",
    "YandexExternalDLPConfig",
    "YandexClipboardAccessByPolicyEnabled",
    "YandexPasteExt",
    "YandexDownloadRestrictionsEnabled",
    "YandexCMURLAllowlistIfNotEnrolled",
    "YandexCustomHeader",
    "YandexNoRefererSettingAllowlist",
    "YandexExtCorpBrowserHeader",
]

RELATED_TERMS = [
    "X-Ybe-Hmac",
    "X-Ybe-Timestamp",
    "X-Ybe-Id",
    "ClipboardRestrictionViolation",
    "DevicePostureViolation",
    "DevicePostureReport",
    "YandexDownloadRestrictionsBlockedUrls",
    "YandexDownloadRestrictionsAllowedUrls",
    "YandexDownloadRestrictionsBlockedTypes",
    "YandexDownloadRestrictionsAllowedTypes",
    "yandex/common/drag_and_drop.js",
]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path):
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def compact_variants(term):
    parts = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", term).lower()
    parts = re.sub(r"[^a-z0-9]+", " ", parts).split()
    variants = {term.lower(), "".join(parts), "_".join(parts), "-".join(parts)}
    if "::" in term:
        variants.add(term.split("::")[-1].lower())
    return sorted(v for v in variants if v)


def find_browser_hits(terms):
    variants = {term: compact_variants(term) for term in terms}
    hits = defaultdict(list)
    for row in read_jsonl(META / "yandex-strings.jsonl"):
        data = row.get("data", {})
        rel = data.get("source_relative_path", "")
        if rel != BROWSER_DLL:
            continue
        value = data.get("value", "")
        lower = value.lower()
        for term, vars_ in variants.items():
            if any(v in lower for v in vars_):
                if len(hits[term]) < 24:
                    hits[term].append({
                        "offset": data.get("offset"),
                        "encoding": data.get("encoding"),
                        "value": value[:500],
                    })
    return hits


def find_source_hits(terms):
    variants = {term: compact_variants(term) for term in terms}
    hits = defaultdict(list)
    for row in read_jsonl(META / "yandex-source-paths.jsonl"):
        data = row.get("data", {})
        rel = data.get("source_relative_path", "")
        if rel != BROWSER_DLL:
            continue
        path = data.get("normalized_path", "")
        lower = path.lower()
        for term, vars_ in variants.items():
            if any(v in lower for v in vars_):
                if len(hits[term]) < 24:
                    hits[term].append({
                        "offset": data.get("offset"),
                        "path": path,
                        "top_component": data.get("top_component"),
                    })
    return hits


def load_policy_priority():
    out = {}
    for row in read_jsonl(META / "policy-priority.jsonl"):
        data = row.get("data", {})
        if data.get("policy_name"):
            out[data["policy_name"]] = data
    return out


def build_seed_pack():
    terms = DIRECT_SEEDS + POLICY_SEEDS + RELATED_TERMS
    string_hits = find_browser_hits(terms)
    path_hits = find_source_hits(terms)
    priorities = load_policy_priority()
    rows = []
    for idx, term in enumerate(terms, 1):
        policy = priorities.get(term, {})
        score = 0
        if term in DIRECT_SEEDS:
            score += 100
        if string_hits.get(term):
            score += 60
        if path_hits.get(term):
            score += 30
        if policy:
            score += min(60, int(policy.get("priority_score") or 0) // 3)
        rows.append({
            "schema": "browser_dll_seed",
            "schema_version": 1,
            "artifact": "artifacts/binaries/yandex-browser-25.6.0.2372/payload/" + BROWSER_DLL,
            "artifact_sha256": "d880aa068a08dc1d1f4b2a5271f340a2ef40f8a5d88f3e797e7fde49d877dfe6",
            "collected_at_utc": now(),
            "extractor": "openyandex-active-ready-pack",
            "extractor_version": "python3-v1",
            "command": ".workflows/tools/build-active-ready-pack.py",
            "confidence": 0.85,
            "data": {
                "rank_hint": idx,
                "term": term,
                "kind": "direct_browser_string" if term in DIRECT_SEEDS else "policy_or_related_seed",
                "score": score,
                "policy_priority": policy.get("priority_score"),
                "policy_classification": policy.get("classification"),
                "policy_families": policy.get("families", []),
                "browser_string_hits": string_hits.get(term, []),
                "browser_source_path_hits": path_hits.get(term, []),
            },
        })
    rows.sort(key=lambda r: (-r["data"]["score"], r["data"]["rank_hint"]))
    with SEEDS_JSONL.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return rows


def collect_status(seed_rows):
    pe_rows = read_jsonl(META / "active-pe-triage.jsonl")
    widget_rows = read_jsonl(META / "active-widget-elf-triage.jsonl")
    pdb_rows = read_jsonl(META / "active-pdb-probes.jsonl")
    priority_rows = read_jsonl(META / "policy-priority.jsonl")
    pdb_head = Counter()
    pdb_range = Counter()
    pdb_hits = []
    for row in pdb_rows:
        probe = row.get("data", {}).get("probe", {})
        head = (probe.get("head_stdout") or "ERR").split(" ", 1)[0]
        ranged = (probe.get("range_status") or "ERR").split(" ", 1)[0]
        pdb_head[head] += 1
        pdb_range[ranged] += 1
        if head == "200" or ranged == "200":
            pdb_hits.append(row.get("data", {}).get("url"))
    return {
        "generated_at_utc": now(),
        "browser_seed_rows": len(seed_rows),
        "browser_seed_top": [r["data"] for r in seed_rows[:12]],
        "pe_triage_rows": len(pe_rows),
        "pe_targets": [r.get("data", {}).get("name") for r in pe_rows],
        "widget_triage_rows": len(widget_rows),
        "widget_targets": [r.get("data", {}).get("name") for r in widget_rows],
        "pdb_probe_rows": len(pdb_rows),
        "pdb_head_status": dict(pdb_head),
        "pdb_range_status": dict(pdb_range),
        "pdb_hits": pdb_hits,
        "policy_priority_rows": len(priority_rows),
        "ghidra_project": "/tmp/opencode/ghidra-projects/yb-25.6.0.2372-speechkit_action_lib",
        "ghidra_log": ".workflows/active-stage/logs/speechkit_action_lib.ghidra.log",
    }


def write_text(status, seed_rows):
    lines = []
    lines.append("Active Reconnaissance Ready Index")
    lines.append("")
    lines.append(f"Generated UTC: {status['generated_at_utc']}")
    lines.append("")
    lines.append("Readiness")
    lines.append("- Static-first workspace is prepared.")
    lines.append("- PE quick triage, widget quick triage, PDB probe, and one Ghidra headless import are complete.")
    lines.append("- Heavy tools capa/FLOSS are opt-in only; do not batch-run them across large C++ DLLs.")
    lines.append("- PE execution remains forbidden unless a VM/snapshot/network capture plan is explicitly approved.")
    lines.append("")
    lines.append("Generated Machine Files")
    lines.append("- .workflows/metadata/browser-dll-seed-pack.jsonl")
    lines.append("- .workflows/metadata/active-pe-triage.jsonl")
    lines.append("- .workflows/metadata/active-widget-elf-triage.jsonl")
    lines.append("- .workflows/metadata/active-pdb-probes.jsonl")
    lines.append("")
    lines.append("Ghidra")
    lines.append(f"- Existing project: {status['ghidra_project']}")
    lines.append(f"- Log: {status['ghidra_log']}")
    lines.append("- First project target: speechkit_action_lib.dll")
    lines.append("- Next Ghidra step: run ExportOpenYandexFacts.java against that project.")
    lines.append("")
    lines.append("Counts")
    lines.append(f"- browser.dll seed rows: {status['browser_seed_rows']}")
    lines.append(f"- policy priority rows: {status['policy_priority_rows']}")
    lines.append(f"- PE triage rows: {status['pe_triage_rows']} ({', '.join(status['pe_targets'])})")
    lines.append(f"- widget triage rows: {status['widget_triage_rows']} ({', '.join(status['widget_targets'])})")
    lines.append(f"- PDB probe rows: {status['pdb_probe_rows']}")
    lines.append(f"- PDB HEAD statuses: {status['pdb_head_status']}")
    lines.append(f"- PDB range statuses: {status['pdb_range_status']}")
    lines.append(f"- PDB hits: {len(status['pdb_hits'])}")
    lines.append("")
    lines.append("Top browser.dll Seeds")
    for row in seed_rows[:20]:
        d = row["data"]
        sh = len(d["browser_string_hits"])
        ph = len(d["browser_source_path_hits"])
        lines.append(f"- score {d['score']:>3} | {d['term']} | kind={d['kind']} | strings={sh} | paths={ph} | policy={d.get('policy_priority')}")
    lines.append("")
    lines.append("Immediate Active Recon Queue")
    lines.append("1. Run Ghidra export script on speechkit_action_lib.dll project and review ActionLibInitialize/ExecuteDirective/ProcessDirective xrefs.")
    lines.append("2. Run browser.dll targeted string/xref search for NetworkService SetYandex* strings, not full manual browsing.")
    lines.append("3. Cluster widget strings for neuro/suggest/coupon endpoints and JSON keys.")
    lines.append("4. Add source_mapping_hypothesis rows only when two independent evidence types agree.")
    lines.append("5. Deprioritize public PDB search unless new symbol hosts/leads appear; current probe had zero hits.")
    lines.append("")
    lines.append("Concrete Commands")
    lines.append("- Build this pack: python3 .workflows/tools/build-active-ready-pack.py")
    lines.append("- PE quick triage: python3 .workflows/tools/static-pe-triage.py all")
    lines.append("- Widget quick triage: python3 .workflows/tools/static-elf-widget-triage.py")
    lines.append("- PDB probe: python3 .workflows/tools/probe-pdb-symbols.py")
    lines.append("- Ghidra project path: /tmp/opencode/ghidra-projects/yb-25.6.0.2372-speechkit_action_lib")
    lines.append("- Browser seed pack: .workflows/active-stage/browser-dll-seed-pack.txt")
    lines.append("")
    OUT_TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_seed_text(seed_rows):
    lines = ["browser.dll Seed Pack", ""]
    lines.append("Use these as targeted string/xref seeds before any full browser.dll pass.")
    lines.append("")
    for row in seed_rows:
        d = row["data"]
        lines.append(f"{d['term']}")
        lines.append(f"- score: {d['score']}")
        lines.append(f"- kind: {d['kind']}")
        if d.get("policy_priority") is not None:
            lines.append(f"- policy: {d.get('policy_priority')} {d.get('policy_classification')} {','.join(d.get('policy_families') or [])}")
        for hit in d["browser_string_hits"][:8]:
            lines.append(f"- string hit: offset={hit.get('offset')} encoding={hit.get('encoding')} value={hit.get('value')}")
        for hit in d["browser_source_path_hits"][:8]:
            lines.append(f"- source path hit: offset={hit.get('offset')} path={hit.get('path')}")
        lines.append("")
    SEEDS_TXT.write_text("\n".join(lines), encoding="utf-8")


def main():
    ACTIVE.mkdir(parents=True, exist_ok=True)
    META.mkdir(parents=True, exist_ok=True)
    seed_rows = build_seed_pack()
    status = collect_status(seed_rows)
    OUT_JSON.write_text(json.dumps(status, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_seed_text(seed_rows)
    write_text(status, seed_rows)
    print(OUT_TXT.relative_to(ROOT))
    print(SEEDS_TXT.relative_to(ROOT))
    print(SEEDS_JSONL.relative_to(ROOT))
    print(OUT_JSON.relative_to(ROOT))


if __name__ == "__main__":
    main()
