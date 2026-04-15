#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mapfile -t shell_scripts < <(git ls-files 'scripts/*.sh' 'scripts/**/*.sh' | LC_ALL=C sort -u)
if ((${#shell_scripts[@]} == 0)); then
  echo "No tracked shell scripts found under scripts/; refusing to run empty shellcheck suite." >&2
  exit 1
fi

shellcheck -x "${shell_scripts[@]}"
