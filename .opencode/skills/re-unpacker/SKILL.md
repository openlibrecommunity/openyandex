---
name: re-unpacker
description: Identify packing or obfuscation indicators and guide safe static-first unpacking for malware triage and reverse engineering. Use for suspicious PE, ELF, Mach-O, APK-adjacent native blobs, packed samples, or unpacking plans.
---

# re-unpacker

## Purpose
Determine whether a sample appears packed or obfuscated and produce a safe, repeatable unpacking plan for defensive analysis.

Default: static-first. Dynamic steps only after explicit engineer approval in a controlled sandbox/VM.

## Use When
- Suspicious PE, ELF, or Mach-O has few strings, anomalous sections, or entropy spikes.
- A malware sample is obfuscated and needs cleaner strings/capa/yara output.
- Sandbox notes suggest in-memory unpacking or decryption.

## Do Not Use When
- There is no safe sandbox and unpacking requires execution.
- The request is to create, modify, hide, or improve malware.

## Inputs
Use any available evidence:
- file metadata: `file`, hashes, size, timestamp
- static triage: sections, imports, entropy, strings, packer signatures, capa
- optional sandbox notes: process tree, API calls, memory map, RWX allocations, dump events

## Guardrails
- Defensive only.
- Never run unknown samples on the host.
- Tie all claims to evidence excerpts.
- Do not invent unpacked artifacts.
- Prefer small commands.
- No EDR bypass, sandbox bypass, or instrumentation tampering guidance.

## Lean Tool Check

```bash
command -v file strings objdump readelf sha256sum sha1sum md5sum upx diec floss capa yara || true
```

## Static Baseline

```bash
sha256sum "<sample>"
sha1sum "<sample>"
md5sum "<sample>"
file "<sample>"
strings -a "<sample>" | head -n 200
strings -el "<sample>" | head -n 200
objdump -h "<sample>" | head -n 200
objdump -x "<sample>" | head -n 260
```

Optional, if installed:

```bash
diec "<sample>"
floss "<sample>" | head -n 200
capa "<sample>"
```

## Packing Signals
Look for multiple independent signals:
- very few readable strings or mostly garbage
- unusual section names, tiny `.text`, huge custom section
- high entropy sections
- minimal imports, loader APIs, `LoadLibrary`, `GetProcAddress`, `dlsym`
- direct packer signatures from DIE/UPX/peframe
- sandbox evidence of RWX allocation, decrypted pages, stub to payload transfer

## Static Unpacking
If evidence shows a known packer with a safe offline unpack path, use that path.

UPX only when evidence supports UPX:

```bash
upx -d "<sample>" -o "<sample>.unpacked"
```

Validate after unpacking:
- section structure changes
- readable strings increase
- imports become richer
- capa hits become more specific
- new artifact hash exists

## Dynamic Gate
If dynamic unpacking is needed, stop and say:

> PAUSE: Unpacking now requires executing the sample. Engineer: approve or deny running in sandbox. If approved, confirm VM snapshot exists, network posture, and monitoring logs to capture. Paste process tree, events, memory or dump indicators, and I will proceed with an evidence-driven unpacking plan.

Keep dynamic guidance high-level and defensive.

## Output
Return:
1. Packing assessment summary, 1-6 bullets with evidence excerpts.
2. Unpacking plan in priority order, static first.
3. Unpacking report with original hashes, produced artifacts, provenance, environment assumptions, safety notes.
4. Next steps for strings, capa, yara, IOC extraction.

## Confidence
Use only:
- `confirmed`
- `high`
- `medium`
- `low`
- `contextual`

## Report Template

### Packing Assessment
- Verdict: packed / likely packed / unclear / likely not packed
- Confidence: <value>
- Evidence:
  - <verbatim excerpt>

### Unpacking Plan
1. <static step> - expected outcome and validation
2. <static step> - expected outcome and validation
3. <sandbox-only step if approved>

### Artifacts
- Original sample:
  - sha256: ...
  - sha1: ...
  - md5: ...
- Unpacked/dumped artifacts, if any:
  - path: ...
  - sha256: ...
  - provenance: ...
  - validation: ...

### Next Steps
- Run `re-ioc-extraction` on strings/logs from the unpacked artifact.
- Run capa/yara and compare original vs unpacked.
- Extract config statically where possible.

## Done
- Defensible assessment with verbatim evidence.
- Prioritized plan respects safety.
- Artifacts have hashes and provenance if produced.
- Clear downstream defensive steps.
