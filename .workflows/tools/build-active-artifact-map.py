#!/usr/bin/env python3
"""Build active-stage artifact map from existing metadata only."""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".workflows" / "metadata"
OUT = ROOT / ".workflows" / "active-stage" / "artifact-map.txt"


def read_jsonl(path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def main():
    files = []
    for row in read_jsonl(META / "yandex-files.jsonl"):
        data = row.get("data", {})
        if data.get("relative_path"):
            files.append(data)

    pe_rows = []
    if (META / "yandex-pe.jsonl").exists():
        for row in read_jsonl(META / "yandex-pe.jsonl"):
            if row.get("schema") == "pe_module":
                pe_rows.append(row.get("data", {}))

    pdb_rows = []
    if (META / "yandex-pdb-index.jsonl").exists():
        for row in read_jsonl(META / "yandex-pdb-index.jsonl"):
            pdb_rows.append(row.get("data", {}) | {"artifact": row.get("artifact")})

    priority = []
    if (META / "policy-priority.jsonl").exists():
        for row in read_jsonl(META / "policy-priority.jsonl"):
            priority.append(row.get("data", {}))

    by_ext = Counter((Path(f["relative_path"]).suffix.lower() or "[none]") for f in files)
    largest = sorted(files, key=lambda x: x.get("size", 0), reverse=True)[:20]

    lines = []
    lines.append("Active Stage Artifact Map")
    lines.append("")
    lines.append(f"Generated UTC: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append("")
    lines.append("Sources")
    lines.append("- Existing metadata only. No new binary analysis performed by this script.")
    lines.append("- .workflows/metadata/yandex-files.jsonl")
    lines.append("- .workflows/metadata/yandex-pe.jsonl")
    lines.append("- .workflows/metadata/yandex-pdb-index.jsonl")
    lines.append("- .workflows/metadata/policy-priority.jsonl")
    lines.append("")
    lines.append("Payload Summary")
    lines.append(f"- files: {len(files)}")
    lines.append(f"- total bytes: {sum(f.get('size', 0) for f in files)}")
    lines.append(f"- PE modules: {len(pe_rows)}")
    lines.append(f"- PDB identities: {len(pdb_rows)}")
    lines.append("")
    lines.append("Extensions")
    for ext, count in by_ext.most_common(25):
        lines.append(f"- {ext}: {count}")
    lines.append("")
    lines.append("Largest Files")
    for f in largest:
        lines.append(f"- {f.get('relative_path')} | {f.get('size')} bytes | {f.get('file_type')}")
    lines.append("")
    lines.append("Priority PE Targets")
    wanted = ["browser.dll", "service_update.exe", "cspeechkit.dll", "speechkit_action_lib.dll", "textclassifier.dll", "browser_elf.dll", "browser_wer.dll"]
    for name in wanted:
        match = next((f for f in files if Path(f.get("relative_path", "")).name.lower() == name), None)
        if match:
            lines.append(f"- {match.get('relative_path')} | sha256 {match.get('sha256')} | {match.get('size')} bytes")
    lines.append("")
    lines.append("Known PDB Identities")
    for row in pdb_rows:
        name = row.get("pdb_name") or row.get("pdb_path")
        if name:
            lines.append(f"- {row.get('artifact')} | {name} | {row.get('guid_age') or row.get('guidage')}")
    lines.append("")
    lines.append("Top Policy Queue")
    for row in priority[:20]:
        lines.append(f"- {row.get('priority_score')} | {row.get('classification')} | {row.get('policy_name')} | {','.join(row.get('families', []))}")
    lines.append("")
    lines.append("Prepared Output Locations")
    lines.append("- .workflows/active-stage/logs/")
    lines.append("- .workflows/active-stage/exports/")
    lines.append("- .workflows/active-stage/tmp/")
    lines.append("- .workflows/active-stage/ghidra/projects/")
    lines.append("- .workflows/active-stage/ghidra/cache/")

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUT.relative_to(ROOT))


if __name__ == "__main__":
    main()
