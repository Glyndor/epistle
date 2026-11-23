#!/usr/bin/env bash
# Cancel the other runs of the commit a failed pull request run belongs to.
#
# It holds a token that can cancel runs, so it runs from the base commit and
# never from the pull request (see the `cancel-others` job of ci.yml), and it
# acts on a closed list of workflows, on runs of the same pull request, the same
# branch and the same commit, and never on its own run. A push, a merge queue
# entry, a schedule, a manual run, a release and every security analysis are
# outside that list, so they cannot be cancelled from here.
#
# It never fails the job: a run that cannot be listed or cancelled is reported
# and left alone, because cancelling is not what makes the pull request red.
#
# Environment: GH_TOKEN, REPO, PR_NUMBER, HEAD_REF, HEAD_SHA, RUN_ID.

set -uo pipefail

# Expensive and functional work only. Not here, on purpose: CodeQL, the
# dependency audits, the secret scan and the DCO check (a functional failure
# must not leave a commit without its analysis), and anything that publishes.
CANCELABLE='["E2E","Database","Container","Interop","LDAP","imaptest","Upgrade","Fuzz"]'

for name in GH_TOKEN REPO PR_NUMBER HEAD_REF HEAD_SHA RUN_ID; do
  if [ -z "${!name:-}" ]; then
    echo "::warning::$name is not set; nothing is cancelled"
    exit 0
  fi
done

if ! runs="$(gh api -X GET "repos/$REPO/actions/runs" \
  -f event=pull_request -f head_sha="$HEAD_SHA" -f per_page=100 \
  --jq ".workflow_runs" 2> /dev/null)"; then
  echo "::warning::could not list the runs of $HEAD_SHA; nothing is cancelled"
  exit 0
fi

if ! ids="$(printf '%s' "$runs" | jq -r \
  --argjson list "$CANCELABLE" --arg sha "$HEAD_SHA" --arg ref "$HEAD_REF" \
  --argjson pr "$PR_NUMBER" --argjson self "$RUN_ID" '
    .[]
    | select(.event == "pull_request")
    | select(.head_sha == $sha and .head_branch == $ref)
    | select(.id != $self)
    | select(.status == "queued" or .status == "in_progress" or .status == "waiting" or .status == "pending")
    | select(any(.pull_requests[]?; .number == $pr))
    | select(.name as $n | $list | index($n))
    | .id' 2> /dev/null)"; then
  echo "::warning::could not read the runs of $HEAD_SHA; nothing is cancelled"
  exit 0
fi

for id in $ids; do
  case "$id" in
    '' | *[!0-9]*) continue ;;
  esac
  if gh api -X POST "repos/$REPO/actions/runs/$id/cancel" > /dev/null 2>&1; then
    echo "cancelled run $id"
  else
    echo "::warning::could not cancel run $id"
  fi
done
exit 0
