#!/usr/bin/env sh
set -eu

log_dir=".workflows/active-stage/logs"
mkdir -p "$log_dir"
out="$log_dir/toolcheck.txt"

{
  printf 'active-stage toolcheck\n'
  date -u '+collected_at_utc %Y-%m-%dT%H:%M:%SZ'
  printf '\n[os]\n'
  uname -a
  printf '\n[tools]\n'
  for tool in \
    file strings objdump readelf llvm-objdump llvm-readobj llvm-pdbutil llvm-undname \
    rabin2 r2 rizin rz-bin ghidraRun analyzeHeadless \
    upx diec floss capa yara jq sqlite3 7z bsdtar \
    sha256sum sha1sum md5sum osslsigncode exiftool python3 go cargo rustc bun node npm git gh curl wget; do
    if command -v "$tool" >/dev/null 2>&1; then
      printf 'ok %s %s\n' "$tool" "$(command -v "$tool")"
    else
      printf 'missing %s\n' "$tool"
    fi
  done
  printf '\n[versions]\n'
  for cmd in \
    'python3 --version' \
    'file --version' \
    'objdump --version' \
    'readelf --version' \
    'llvm-objdump --version' \
    'llvm-readobj --version' \
    'llvm-pdbutil --version' \
    'llvm-undname --version' \
    'rabin2 -v' \
    'r2 -v' \
    'rizin -v' \
    'rz-bin -v' \
    'analyzeHeadless -version' \
    'upx --version' \
    'diec --version' \
    'floss --version' \
    'capa --version' \
    'yara --version' \
    'jq --version' \
    'sqlite3 --version' \
    '7z' \
    'bsdtar --version' \
    'osslsigncode --version' \
    'exiftool -ver' \
    'go version' \
    'cargo --version' \
    'rustc --version' \
    'bun --version' \
    'node --version' \
    'npm --version' \
    'git --version' \
    'gh --version'; do
    printf '$ %s\n' "$cmd"
    sh -c "$cmd" 2>&1 | sed -n '1,5p' || true
  done
} > "$out"

printf '%s\n' "$out"
