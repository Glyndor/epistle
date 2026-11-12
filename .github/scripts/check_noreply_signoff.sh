#!/usr/bin/env bash
# Fails when a commit in BASE..HEAD names a personal address as its author or in
# a Signed-off-by / Co-authored-by trailer. Only GitHub noreply addresses may
# appear: <id>+<login>@users.noreply.github.com, <login>@users.noreply.github.com,
# noreply@github.com (web-flow) and support@github.com (dependabot[bot]).
#
#   bash check-noreply-signoff.sh BASE_SHA HEAD_SHA
set -euo pipefail

base="${1:-}"
head="${2:-}"
if [ -z "$base" ] || [ -z "$head" ]; then
  echo "::error::usage: check-noreply-signoff.sh BASE_SHA HEAD_SHA"
  exit 2
fi

allowed() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    *@users.noreply.github.com | noreply@github.com | support@github.com) return 0 ;;
    *) return 1 ;;
  esac
}

bad=0
for sha in $(git rev-list --no-merges "${base}..${head}"); do
  author="$(git show -s --format='%ae' "$sha")"
  if ! allowed "$author"; then
    echo "::error::commit $sha has author address '$author', which is not a GitHub noreply address"
    bad=1
  fi
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    email="$(printf '%s' "$line" | sed -n 's/.*<\([^>]*\)>.*/\1/p')"
    if [ -z "$email" ] || ! allowed "$email"; then
      echo "::error::commit $sha has trailer '$line' with an address that is not a GitHub noreply address"
      bad=1
    fi
  done < <(git show -s --format='%(trailers:key=Signed-off-by,key=Co-authored-by,valueonly=false,unfold=true)' "$sha")
done

if [ "$bad" -ne 0 ]; then
  echo "Sign and author with the noreply address from 'git config user.email'; a personal address must never reach a public history."
  exit 1
fi
echo "Every author and sign-off address is a GitHub noreply address."
