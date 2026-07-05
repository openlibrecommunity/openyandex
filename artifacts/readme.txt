local artifacts

purpose:
- binaries/
- samples/
- tools/

these folders are ignored by git.

rule:
- downloaded installers, unpacked browser trees, symbols, pdbs, dwarf/debug files, and local tools go here.
- do not commit binaries.
