---
name: re-ioc-extraction
description: Extract and normalize defensive IOCs from strings output, sandbox logs, network logs, or reverse engineering notes. Use when the user wants IOCs for detection, blocking, hunting, or reporting.
---

# re-ioc-extraction

## Purpose
Produce a complete, defensive IOC set from analyst-provided evidence and present it in:
1. a Markdown IOC table
2. a structured YAML list

Use traceable evidence only: no guessing, no enrichment, no validation.

## Inputs
Use at least one:
- strings output, ASCII or UTF-16
- sandbox, EDR, process, file, registry, or network logs
- packet, proxy, DNS logs, or extracted HTTP requests
- RE notes: imports, APIs, decompiled snippets, paths, config blobs
- trusted known hashes

If evidence is missing, still output what is present and note gaps.

## Static Evidence Generation
Do not execute samples. If execution is requested or required, pause and ask for engineer approval in a controlled sandbox/VM.

Prefer small commands:

```bash
command -v file strings sha256sum sha1sum md5sum capa jq || true
file "<sample>"
sha256sum "<sample>"
sha1sum "<sample>"
md5sum "<sample>"
strings -a "<sample>" > /tmp/sample.strings.txt
strings -el "<sample>" > /tmp/sample.strings.utf16.txt
rg -n -F "http://" /tmp/sample.strings.txt
rg -n -F "https://" /tmp/sample.strings.txt
rg -n -F ".onion" /tmp/sample.strings.txt
rg -n -F "HKEY_" /tmp/sample.strings.utf16.txt
rg -n -F "CurrentVersion\\Run" /tmp/sample.strings.utf16.txt
```

## Rules
1. Only output indicators explicitly present in evidence.
2. Label ambiguous or partial values as `candidate` or `incomplete`.
3. Do not resolve domains, visit URLs, or validate infra.
4. Every IOC needs a verbatim evidence snippet and source artifact.
5. Do not inspect unrelated environment files unless asked.
6. Do not infer missing C2, persistence, or behavior as IOCs.
7. Do not run unknown samples.

If execution is required, say:

> PAUSE: This step would require executing an unknown sample. I will not proceed automatically. Confirm whether to run in a controlled sandbox/VM and provide sandbox constraints. Paste sandbox outputs here and I will extract IOCs from evidence.

## IOC Types
- hashes: md5, sha1, sha256
- network: domains, IPs, URLs, URI paths, ports, SNI, Host headers
- email addresses
- file paths and file names
- registry keys, values, data
- service names, scheduled task names, mutexes
- user agents
- process names and command lines
- certificate subjects, thumbprints, public keys

## Normalization
- Domains: lowercase, strip surrounding punctuation, keep subdomains.
- URLs: preserve as-seen; for `hxxp` include obfuscated and normalized forms.
- Hashes: lowercase; do not fix missing chars.
- Paths/registry: preserve exact text.
- Only apply reversible obvious transforms, such as `hxxp` to `http` and `[.]` to `.`.

## Confidence
Use only:
- `confirmed`
- `high`
- `medium`
- `low`
- `contextual`
- `candidate`
- `incomplete`

## Output
Always produce both.

### IOC Table
Columns:
- Type
- Indicator
- Confidence
- Context
- Evidence

One indicator per row. Evidence is an exact line or tight excerpt.

### YAML
Top-level keys only when entries exist:
- `hashes`
- `network`
- `file_paths`
- `file_names`
- `process_names`
- `registry`
- `mutexes`
- `user_agents`
- `emails`
- `certificates`
- `notes`
- `static_risk_notes`

Each item needs:
- `value`
- `confidence`
- `source`
- `evidence_snippet`

Extra fields:
- `hashes[]`: `algorithm`
- `network[]`: `kind`
- `registry[]`: `kind` when known
- `certificates[]`: `kind` when known

## Done
- Every indicator is in evidence and has a verbatim snippet.
- YAML uses the schema and allowed confidence labels.
- No live validation or enrichment.
- Risk notes are brief and evidence-cited if requested.
