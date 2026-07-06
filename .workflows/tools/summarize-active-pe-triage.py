#!/usr/bin/env python3
"""Summarize active PE triage logs into a small durable text report."""

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".workflows" / "metadata"
OUT = ROOT / ".workflows" / "active-stage" / "exports" / "active-pe-triage-summary.txt"


def read(path):
    if not path:
        return ""
    p = ROOT / path
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def import_dlls(text):
    return sorted(set(re.findall(r"Name:\s+([^\s]+\.dll|[^\s]+\.DLL)", text)))


def exports(text):
    return re.findall(r"Name:\s+([^\s]+)", text)


def pdb_path(text):
    match = re.search(r"PDBFileName:\s*(.+)", text)
    if match:
        return match.group(1).strip()
    match = re.search(r"dbg_file\s+([^\n\x1b]+)", text)
    if match:
        return match.group(1).strip()
    return None


def signature_status(text):
    statuses = re.findall(r"Signature verification:\s*(.+)", text)
    return [s.strip() for s in statuses]


def main():
    rows = []
    with (META / "active-pe-triage.jsonl").open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))

    lines = ["Active PE Triage Summary", ""]
    lines.append("Scope")
    lines.append("- Static-only quick pass.")
    lines.append("- Heavy tools capa/FLOSS skipped by default after FLOSS timeout on cspeechkit.dll.")
    lines.append("- No PE execution performed.")
    lines.append("")

    for row in rows:
        data = row["data"]
        logs = data["logs"]
        imports_text = read(logs.get("llvm-readobj-imports"))
        exports_text = read(logs.get("llvm-readobj-exports"))
        codeview_text = read(logs.get("llvm-readobj-codeview")) + "\n" + read(logs.get("rz-bin-info"))
        sig_text = read(logs.get("osslsigncode"))
        lines.append(data["name"])
        lines.append(f"- artifact: {row['artifact']}")
        lines.append(f"- sha256: {row['artifact_sha256']}")
        lines.append(f"- size: {data['size']}")
        pdb = pdb_path(codeview_text)
        if pdb:
            lines.append(f"- pdb path: {pdb}")
        sigs = signature_status(sig_text)
        if sigs:
            lines.append(f"- signature status: {', '.join(sigs)}")
        dlls = import_dlls(imports_text)
        lines.append(f"- imported dlls ({len(dlls)}): {', '.join(dlls[:24])}")
        exps = exports(exports_text)
        lines.append(f"- exports ({len(exps)}): {', '.join(exps[:16]) if exps else '-'}")
        lines.append(f"- string categories: {', '.join(data.get('string_hit_categories', [])) or '-'}")
        lines.append(f"- DIE categories: {', '.join(data.get('die_hit_categories', [])) or '-'}")
        lines.append("")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(OUT.relative_to(ROOT))


if __name__ == "__main__":
    main()
