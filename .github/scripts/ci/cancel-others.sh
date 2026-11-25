#!/usr/bin/env bash
#
# Cut the rest of a commit's runs when one job has failed. Called by the `cancel` job of
# reusable-cancel-others.yml, which holds `actions: write` and nothing else, and which runs the
# copy of this script that the BASE commit holds, never the one in the pull request's tree.
#
# Inputs (env):
#   GH_TOKEN     token with `actions: write`.
#   REPO         owner/name.
#   RUN_ID       the run this job belongs to.
#   EVENT_NAME   `pull_request` or `merge_group`; anything else cancels nothing.
#   CANCEL_OWN   `true` to also cancel the run this job belongs to, which ends the jobs of it that
#                have not finished. `CI gate` runs whatever happened (`if: always()`) and fails on a
#                job that was cancelled, so the run is red and not green.
#   HEAD_SHA     the pull request's head commit (pull_request only).
#   HEAD_BRANCH  the pull request's head branch (pull_request only).
#
# What it cancels, and only that:
#   - on a pull request, the other runs of the `pull_request` event for the same head commit and the
#     same head branch, from this repository, that have not finished, whose workflow file is in
#     CANCELLABLE below;
#   - with CANCEL_OWN, the run it belongs to, last, on a pull request and in the merge queue.
# In the merge queue it cancels nothing but its own run: the other runs of a queue entry belong to
# the queue.
#
# What it never cancels, whatever it is called: a run of `push`, `merge_group` (other than its own),
# `schedule` or `workflow_dispatch`, a release or a publication, and any analysis of security.
# Those workflows are not in the list, and the test (.github/scripts/ci_gate/test_cancel_others.py)
# fails when a workflow whose name says it is one is added to it.
#
# It never fails: a listing that cannot be read or a cancellation that is refused (a token that is
# read-only, as it is for Dependabot and forks) is reported and the job still succeeds. Cancelling
# changes nothing about the result of the job that failed, so the pull request stays red.
set -uo pipefail

# The workflows a failure may cancel: the expensive and functional ones. DCO,
# the secret scan and commit identity, the dependency audit and CodeQL are not here and must not be:
# a failure of tests cannot leave a commit without its analysis.
CANCELLABLE=(
	.github/workflows/ci.yml
	.github/workflows/db.yml
	.github/workflows/e2e.yml
	.github/workflows/upgrade.yml
	.github/workflows/container.yml
	.github/workflows/interop.yml
	.github/workflows/imaptest.yml
	.github/workflows/ldap.yml
	.github/workflows/fuzz.yml
)

repo="${REPO:-}"
own="${RUN_ID:-}"
event="${EVENT_NAME:-}"
sha="${HEAD_SHA:-}"
branch="${HEAD_BRANCH:-}"
if [ -z "$repo" ] || [ -z "$own" ]; then
	echo "::warning::cancel-others: a required input is missing; nothing is cancelled"
	exit 0
fi
case "$own" in
	*[!0-9]*) echo "::warning::cancel-others: the run id is not a number; nothing is cancelled"; exit 0 ;;
esac
case "$event" in
	pull_request | merge_group) ;;
	*) echo "::warning::cancel-others: the event is not a pull request or the merge queue; nothing is cancelled"; exit 0 ;;
esac

cancel_others() {
	if [ -z "$sha" ] || [ -z "$branch" ]; then
		echo "::warning::cancel-others: the head commit or branch is missing; no other run is cancelled"
		return 0
	fi
	case "$sha" in
		*[!0-9a-f]*) echo "::warning::cancel-others: the head commit is not a hash; no other run is cancelled"; return 0 ;;
	esac
	if ! listing="$(gh api "repos/${repo}/actions/runs?head_sha=${sha}&event=pull_request&per_page=100" 2>/dev/null)"; then
		echo "::warning::cancel-others: the run list could not be read; no other run is cancelled"
		return 0
	fi
	# One run per line: id, status, path. The environment carries the values, so
	# nothing is spliced into the filter.
	if ! runs="$(
		printf '%s' "$listing" | REPO="$repo" OWN="$own" SHA="$sha" BRANCH="$branch" jq -r '
			.workflow_runs[]?
			| select(.event == "pull_request"
				and .head_sha == env.SHA
				and .head_branch == env.BRANCH
				and (.head_repository.full_name // "") == env.REPO
				and (.id | tostring) != env.OWN
				and (.status == "queued" or .status == "in_progress" or .status == "waiting" or .status == "pending"))
			| [(.id | tostring), (.path // "" | split("@")[0])]
			| @tsv' 2>/dev/null
	)"; then
		echo "::warning::cancel-others: the run list could not be read; no other run is cancelled"
		return 0
	fi
	while IFS=$'\t' read -r id path; do
		[ -n "$id" ] || continue
		listed=0
		for workflow in "${CANCELLABLE[@]}"; do
			[ "$path" = "$workflow" ] && listed=1
		done
		if [ "$listed" -eq 0 ]; then
			echo "kept: run $id of ${path:-an unnamed workflow} is not on the list"
			continue
		fi
		if gh api -X POST "repos/${repo}/actions/runs/${id}/cancel" >/dev/null 2>&1; then
			echo "cancelled: run $id of $path"
		else
			echo "::warning::cancel-others: run $id of $path could not be cancelled"
		fi
	done <<<"$runs"
}

[ "$event" != pull_request ] || cancel_others

# The own run goes last: the request ends this very job.
if [ "${CANCEL_OWN:-false}" = true ]; then
	if gh api -X POST "repos/${repo}/actions/runs/${own}/cancel" >/dev/null 2>&1; then
		echo "cancelled: this run ($own)"
	else
		echo "::warning::cancel-others: this run ($own) could not be cancelled"
	fi
fi
exit 0
