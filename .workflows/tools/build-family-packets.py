#!/usr/bin/env python3
"""Build human-readable family packets from diff chunks."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".workflows" / "metadata"
ACTIVE = ROOT / ".workflows" / "active-stage"
OUTDIR = ACTIVE / "family-packets"


def read_jsonl(path):
    return [json.loads(line) for line in path.open("r", encoding="utf-8") if line.strip()]


def main():
    OUTDIR.mkdir(parents=True, exist_ok=True)
    chunks = read_jsonl(META / "diff-chunks-v1.jsonl")
    families = sorted({row["data"]["assigned_family"] for row in chunks if row["data"]["assigned_family"] != "unknown"})
    for family in families:
        rows = [row for row in chunks if row["data"]["assigned_family"] == family]
        lines = [f"Family Packet: {family}", ""]
        lines.append(f"Diff chunks: {len(rows)}")
        lines.append("")
        for row in rows:
            d = row["data"]
            lines.append(f"{d['chunk_id']}")
            lines.append(f"- kind: {d['kind']}")
            lines.append(f"- title: {d['title']}")
            lines.append(f"- status: {d['status']}")
            lines.append(f"- evidence count: {len(d['evidence'])}")
            for ev in d["evidence"][:80]:
                extra = []
                if ev.get("offset") is not None:
                    extra.append(f"offset={ev.get('offset')}")
                if ev.get("artifact"):
                    extra.append(f"artifact={ev.get('artifact')}")
                suffix = " | " + ", ".join(extra) if extra else ""
                lines.append(f"  - {ev.get('kind')}: {ev.get('value')}{suffix}")
            lines.append("")
        lines.append("Next actions")
        lines.append("- Validate each chunk with targeted Ghidra xrefs where needed.")
        lines.append("- Promote chunks to mapped_keep/drop/defer after evidence review.")
        lines.append("- Create implementation tasks only after Chromium touch points are named.")
        (OUTDIR / f"{family}.txt").write_text("\n".join(lines), encoding="utf-8")
    print(OUTDIR.relative_to(ROOT))


if __name__ == "__main__":
    main()
