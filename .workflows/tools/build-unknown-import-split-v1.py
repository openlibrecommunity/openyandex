#!/usr/bin/env python3
"""Split the residual rizin-imports-unknown bucket into smaller decisions."""

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
META = ROOT / ".workflows" / "metadata"
ACTIVE = ROOT / ".workflows" / "active-stage"
OUT = META / "unknown-import-split-v1.jsonl"
TXT = ACTIVE / "unknown-import-split-v1.txt"


RULES = [
    ("browser_elf_baseline_equivalent", "drop_baseline_equivalent", ["GetUserDataDirectoryThunk", "IsTemporaryUserDataDirectoryCreatedForHeadless"], "Same thunk names exist in Chrome baseline under CHROME_ELF.DLL; Yandex libname rename is not product evidence."),
    ("uwp_package_lookup", "defer_os_integration", ["GetPackagePathByFullName", "GetPackagesByPackageFamily"], "Windows package lookup plumbing; keep only if tied to visible install/web-app behavior."),
    ("ipc_pipe_process_runtime", "defer_runtime_plumbing", ["CreatePipe", "DisconnectNamedPipe", "TerminateThread"], "Generic child-process/IPC runtime imports; no Yandex family proof yet."),
    ("console_runtime", "defer_runtime_plumbing", ["GetConsoleScreenBufferInfo", "SetConsoleMode"], "Console mode/runtime support; not user-visible browser feature evidence."),
    ("sync_wait_runtime", "defer_runtime_plumbing", ["CreateWaitableTimerW", "OpenEventW", "OpenMutexW"], "Generic synchronization/runtime imports; no product family proof yet."),
    ("path_string_helpers", "defer_runtime_plumbing", ["GetFinalPathNameByHandleA", "SetFileApisToANSI", "SetFileApisToOEM", "lstrcmpA", "lstrcpynW", "lstrlenW"], "Generic path/string compatibility imports; no product family proof yet."),
    ("network_error_helper", "defer_runtime_plumbing", ["WSASetLastError"], "Socket error helper; no Yandex networking feature proof by itself."),
    ("com_security_runtime", "defer_runtime_plumbing", ["CoInitializeSecurity"], "Generic COM security initialization; no product family proof yet."),
]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path):
    return [json.loads(line) for line in path.open("r", encoding="utf-8") if line.strip()]


def unknown_imports():
    for row in read_jsonl(META / "diff-chunks-v1.jsonl"):
        d = row["data"]
        if d.get("chunk_id") == "rizin-imports-unknown":
            return [ev.get("value") for ev in d.get("evidence", []) if ev.get("value")]
    return []


def classify(value):
    name = value.rsplit("::", 1)[-1]
    lower_name = name.lower()
    for group, status, names, rationale in RULES:
        if any(n.lower() == lower_name for n in names):
            return group, status, rationale
    return "still_unknown", "needs_manual_assignment", "No split rule matched."


def main():
    groups = defaultdict(list)
    metadata = {}
    for value in unknown_imports():
        group, status, rationale = classify(value)
        groups[group].append(value)
        metadata[group] = (status, rationale)

    rows = []
    for group, imports in sorted(groups.items()):
        status, rationale = metadata[group]
        rows.append({
            "schema": "unknown_import_split_v1",
            "schema_version": 1,
            "artifact": None,
            "artifact_sha256": None,
            "collected_at_utc": now(),
            "extractor": "openyandex-unknown-import-split-builder",
            "extractor_version": "python3-v1",
            "command": ".workflows/tools/build-unknown-import-split-v1.py",
            "confidence": 0.74,
            "data": {
                "parent_chunk_id": "rizin-imports-unknown",
                "split_id": f"rizin-imports-unknown-{group}",
                "status": status,
                "rationale": rationale,
                "imports": sorted(imports),
                "import_count": len(imports),
            },
        })

    with OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    counts = Counter(row["data"]["status"] for row in rows)
    lines = ["Unknown Import Split v1", "", "Status counts:"]
    for key, value in sorted(counts.items()):
        lines.append(f"- {key}: {value}")
    lines.append("")
    for row in rows:
        d = row["data"]
        lines.append(f"{d['split_id']} | {d['status']} | imports={d['import_count']}")
        lines.append(f"- {d['rationale']}")
        for imp in d["imports"]:
            lines.append(f"- {imp}")
    TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(OUT.relative_to(ROOT))
    print(TXT.relative_to(ROOT))


if __name__ == "__main__":
    main()
