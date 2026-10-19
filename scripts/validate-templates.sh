#!/usr/bin/env bash
set -euo pipefail

# Validate every Terraform module under templates/<provider>/<component>.
# Runs `terraform fmt -check` and `terraform validate` (after backend-less init).
# Portable to bash 3.2 (macOS default): no mapfile, no process substitution.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v terraform >/dev/null 2>&1; then
  echo "error: terraform not found on PATH" >&2
  exit 2
fi

count=0
while IFS= read -r mod; do
  [ -n "$mod" ] || continue
  count=$((count + 1))
  echo "==> $mod"
  (cd "$mod" && terraform fmt -check -no-color)
  (cd "$mod" && terraform init -backend=false -input=false -no-color >/dev/null)
  (cd "$mod" && terraform validate -no-color)
done < <(find "$repo_root/templates" -name main.tf -type f -exec dirname {} \; | sort -u)

if [ "$count" -eq 0 ]; then
  echo "no modules found under templates/" >&2
  exit 1
fi

echo "validated $count module(s): all formatted and valid"
