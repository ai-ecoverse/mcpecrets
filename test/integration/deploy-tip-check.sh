#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
workflow="$root/.github/workflows/deploy.yml"
script="$(awk '
  /name: Check run is for the tip of main/ { found=1; next }
  found && /run: \|/ { body=1; next }
  body && /^      - / { exit }
  body && NF { sub(/^          /, ""); print }
' "$workflow")"
[ -n "$script" ] || { echo "FAIL: tip check step missing"; exit 1; }
grep -q "if: steps.tip.outputs.current == 'true'" "$workflow" || { echo "FAIL: deploy not gated on tip check"; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git init -q --bare -b main "$work/origin.git"
git clone -q "$work/origin.git" "$work/clone" 2>/dev/null
cd "$work/clone"
git -c user.name=t -c user.email=t@t commit -q --allow-empty -m one
git push -q origin HEAD:main
old="$(git rev-parse HEAD)"
run() { GITHUB_SHA="$1" GITHUB_OUTPUT="$work/out" bash -c "$script" >/dev/null; cat "$work/out"; rm -f "$work/out"; }
[ "$(run "$old")" = "current=true" ] || { echo "FAIL: tip run not deployed"; exit 1; }
git -c user.name=t -c user.email=t@t commit -q --allow-empty -m two
git push -q origin HEAD:main
[ "$(run "$old")" = "current=false" ] || { echo "FAIL: stale run not skipped"; exit 1; }
[ "$(run "$(git rev-parse HEAD)")" = "current=true" ] || { echo "FAIL: new tip not deployed"; exit 1; }
echo "PASS"
