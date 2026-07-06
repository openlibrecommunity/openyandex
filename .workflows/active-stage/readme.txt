active-stage workspace

purpose:
- preparation area for static reverse engineering work.
- keep commands reproducible before touching heavy binaries.

tracked:
- readme.txt
- runbook.txt
- artifact-map.txt
- ghidra/readme.txt
- logs/.gitkeep
- exports/.gitkeep
- tmp/.gitkeep

ignored/heavy outputs:
- ghidra/projects/
- ghidra/cache/
- logs/*
- exports/*
- tmp/*

rule:
- do not execute PE samples on host.
- static-first only.
- write raw tool output to .workflows/active-stage/logs/ or exports/.
- write durable conclusions to notes/re/.
