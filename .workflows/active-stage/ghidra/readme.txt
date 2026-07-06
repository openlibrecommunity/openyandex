ghidra workspace

expected local dirs:
- projects/ - ignored Ghidra project storage.
- cache/ - ignored import/cache/output staging.

preferred mode:
- use analyzeHeadless for reproducible imports and exports.
- keep project names deterministic: yb-25.6.0.2372-<module>.
- keep raw logs under .workflows/active-stage/logs/.

safety:
- static import only.
- no sample execution on host.
