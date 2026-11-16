#!/usr/bin/env bash
# Prove that a stack comes back after a reboot, on a machine that can be
# thrown away. Two steps, because the reboot ends the process that asked for it:
#
#   stack-reboot.sh before --yes-reboot   record the state, then reboot
#   stack-reboot.sh after [--wait SECS]   after the reboot: verify and report
#
# `after` passes only when the boot area of `epistle status` is ok (boot unit
# did not fail, every service that should run is up), a reboot really happened,
# and no container was recreated and no image appeared: a reboot only brings
# the existing containers up, it never builds, pulls or recreates.
#
# Internal, also usable alone: `compare BEFORE_DIR AFTER_DIR`, `judge FILE`.
# See docs/operations/reboot-test.md.
set -euo pipefail
export LC_ALL=C

readonly ACCOUNT_DEFAULT=glyndor-epistle
EPISTLE_BIN=${EPISTLE_BIN:-epistle}
STATE_DIR=${STACK_REBOOT_STATE:-/var/lib/stack-reboot}
MARKER=${STACK_REBOOT_MARKER:-/etc/epistle-disposable}
BOOT_ID_FILE=${STACK_REBOOT_BOOT_ID:-/proc/sys/kernel/random/boot_id}
REBOOT_CMD=${STACK_REBOOT_CMD:-systemctl reboot}
INTERVAL=${STACK_REBOOT_INTERVAL:-10}
ACCOUNT=${STACK_REBOOT_ACCOUNT:-$ACCOUNT_DEFAULT}

die() {
	printf 'stack-reboot: %s\n' "$*" >&2
	exit "${EXIT_CODE:-2}"
}

usage() {
	cat <<'USAGE'
usage: stack-reboot.sh before [--yes-reboot] [--dry-run] [--force-not-disposable]
       stack-reboot.sh after [--wait SECS]
       stack-reboot.sh clean
       stack-reboot.sh compare BEFORE_DIR AFTER_DIR
       stack-reboot.sh judge JSON_FILE

before   records the state and reboots this machine. Refuses without
         --yes-reboot, and on a machine without the marker file
         (/etc/epistle-disposable) unless --force-not-disposable is given.
         --dry-run prints what it would do and changes nothing.
after    run after the machine is back; waits up to SECS (default 300) for the
         boot area to be ok, then compares the state with the one recorded.
clean    removes the recorded state and the report.
Exit: 0 passed, 1 verification failed, 2 usage or refused.
USAGE
}

# Pure: judge a `status --json` or `check boot --json` document. Prints one
# line per boot item that is not ok. Passes (0) only when the boot area is
# present and ok and carries the two items that matter after a reboot.
judge() {
	local file=$1 problems
	[[ -r $file ]] || {
		echo "no status document at $file"
		return 1
	}
	if ! jq -e 'type == "object" and (.boot | type == "object")' "$file" >/dev/null 2>&1; then
		echo "the document has no boot area"
		return 1
	fi
	problems=$(jq -r '
		.boot as $b
		| (if $b.status == "ok" then empty else "boot area is \($b.status): \($b.detail | tostring | .[0:300])" end),
		  ($b.items // [] | .[] | select(.status != "ok")
		    | "\(.name): \(.status): \(.detail | tostring | .[0:300])"),
		  (["boot unit", "services"][] as $need
		    | select(($b.items // []) | map(.name) | index($need) | not)
		    | "the boot area has no \($need) item, so nothing was judged")
	' "$file")
	if [[ -n $problems ]]; then
		printf '%s\n' "$problems"
		return 1
	fi
	return 0
}

# Pure: compare two recorded states (directories with containers.tsv and
# images.txt). Every difference that means something was recreated, rebuilt or
# pulled, or that a container is not running, is a line on stdout and a failure.
compare() {
	local before=$1 after=$2 bad=0 line name id image created state a_id a_image a_created a_state
	local -A seen=()
	for f in "$before/containers.tsv" "$after/containers.tsv" "$before/images.txt" "$after/images.txt"; do
		[[ -r $f ]] || {
			echo "missing recorded state: $f"
			return 1
		}
	done
	declare -A now=()
	while IFS=$'\t' read -r name id image created state; do
		[[ -n $name ]] && now[$name]="$id	$image	$created	$state"
	done <"$after/containers.tsv"
	while IFS=$'\t' read -r name id image created state; do
		[[ -n $name ]] || continue
		seen[$name]=1
		if [[ -z ${now[$name]:-} ]]; then
			echo "container $name is gone"
			bad=1
			continue
		fi
		IFS=$'\t' read -r a_id a_image a_created a_state <<<"${now[$name]}"
		if [[ $a_id != "$id" || $a_created != "$created" ]]; then
			echo "container $name was recreated (id $id -> $a_id, created $created -> $a_created)"
			bad=1
		fi
		if [[ $a_image != "$image" ]]; then
			echo "container $name runs another image ($image -> $a_image)"
			bad=1
		fi
		if [[ $state == running && $a_state != running ]]; then
			echo "container $name was running and is $a_state"
			bad=1
		fi
	done <"$before/containers.tsv"
	for name in "${!now[@]}"; do
		if [[ -z ${seen[$name]:-} ]]; then
			echo "container $name did not exist before the reboot"
			bad=1
		fi
	done
	while IFS= read -r line; do
		[[ -n $line ]] || continue
		if ! grep -qxF -- "$line" "$before/images.txt"; then
			echo "image $line appeared after the reboot (a pull or a build)"
			bad=1
		fi
	done <"$after/images.txt"
	return "$bad"
}

podman_cmd() {
	if [[ -n ${STACK_REBOOT_PODMAN:-} ]]; then
		# shellcheck disable=SC2086 # a command line on purpose, set by the operator or a test
		$STACK_REBOOT_PODMAN "$@"
	else
		local uid
		uid=$(id -u "$ACCOUNT")
		runuser -u "$ACCOUNT" -- env "XDG_RUNTIME_DIR=/run/user/$uid" podman "$@"
	fi
}

# Record names, ids, image ids, creation times and states: nothing else, so the
# files hold no configuration and no secret.
snapshot() {
	local dir=$1
	mkdir -p "$dir"
	podman_cmd ps -a --format '{{.Names}}	{{.ID}}	{{.ImageID}}	{{.Created}}	{{.State}}' | sort >"$dir/containers.tsv"
	podman_cmd images --format '{{.ID}}' | sort -u >"$dir/images.txt"
}

fetch_boot() {
	# `check boot --json` exits 1 when the area fails; the document is what counts.
	"$EPISTLE_BIN" check boot --json >"$1" 2>/dev/null || true
}

print_plan() {
	cat <<PLAN
stack-reboot will, on this machine:
  1. check the boot area of epistle is ok now (it cannot prove anything otherwise)
  2. record container ids, image ids, creation times and the boot id in $STATE_DIR
  3. reboot with: $REBOOT_CMD
After the reboot, \`stack-reboot.sh after\` checks that the boot area is ok, that
no container was recreated and that no image was pulled or built.
PLAN
}

cmd_before() {
	local yes=0 dry=0 force=0
	while (($#)); do
		case $1 in
		--yes-reboot) yes=1 ;;
		--dry-run) dry=1 ;;
		--force-not-disposable) force=1 ;;
		*) die "unknown option $1" ;;
		esac
		shift
	done
	print_plan
	if ((dry)); then
		((yes)) || echo "dry run: a real run would be refused without --yes-reboot"
		[[ -e $MARKER || $force -eq 1 ]] || echo "dry run: a real run would be refused, $MARKER does not exist"
		echo "dry run: nothing was recorded and nothing was rebooted"
		return 0
	fi
	((yes)) || die "refusing to reboot without --yes-reboot"
	if [[ ! -e $MARKER ]] && ((!force)); then
		die "refusing: this machine is not marked disposable ($MARKER does not exist); create it on a throwaway machine, or pass --force-not-disposable"
	fi
	local tmp=$WORK/doc.json
	fetch_boot "$tmp"
	if ! judge "$tmp" >/dev/null; then
		judge "$tmp" >&2 || true
		EXIT_CODE=1 die "the boot area is not ok before the reboot; fix it first"
	fi
	rm -rf "$STATE_DIR"
	(umask 077 && mkdir -p "$STATE_DIR")
	snapshot "$STATE_DIR/before"
	cp -- "$BOOT_ID_FILE" "$STATE_DIR/boot_id"
	echo "recorded the state in $STATE_DIR; rebooting now"
	$REBOOT_CMD
}

cmd_after() {
	local wait=300 tmp=$WORK/doc.json deadline verdict=0 report out
	while (($#)); do
		case $1 in
		--wait)
			shift
			[[ ${1:-} =~ ^[0-9]+$ ]] || die "--wait takes a number of seconds"
			wait=$1
			;;
		*) die "unknown option $1" ;;
		esac
		shift
	done
	[[ -r $STATE_DIR/boot_id ]] || die "no recorded state in $STATE_DIR; run \`before\` first"
	report=$STATE_DIR/report.txt
	: >"$report"
	say() { printf '%s\n' "$*" | tee -a "$report"; }
	if [[ $(<"$BOOT_ID_FILE") == "$(<"$STATE_DIR/boot_id")" ]]; then
		say "FAIL the boot id did not change: the machine did not reboot"
		EXIT_CODE=1 die "no reboot happened"
	fi
	say "reboot confirmed (the boot id changed)"
	deadline=$((SECONDS + wait))
	while :; do
		fetch_boot "$tmp"
		if judge "$tmp" >/dev/null; then
			break
		fi
		if ((SECONDS >= deadline)); then
			say "FAIL the boot area is not ok after ${wait}s:"
			judge "$tmp" | sed 's/^/  /' | tee -a "$report"
			verdict=1
			break
		fi
		sleep "$INTERVAL"
	done
	if ((!verdict)); then
		# The whole-status document must agree with the one-area check.
		"$EPISTLE_BIN" status --json >"$tmp" 2>/dev/null || true
		if out=$(judge "$tmp"); then
			say "ok   the boot area is ok: the boot unit did not fail and every service that should run is up"
		else
			say "FAIL \`epistle status --json\` disagrees:"
			printf '%s\n' "$out" | sed 's/^/  /' | tee -a "$report"
			verdict=1
		fi
	fi
	if snapshot "$STATE_DIR/after" 2>/dev/null; then
		if out=$(compare "$STATE_DIR/before" "$STATE_DIR/after"); then
			say "ok   no container was recreated and no image appeared"
		else
			say "FAIL the reboot changed the stack:"
			printf '%s\n' "$out" | sed 's/^/  /' | tee -a "$report"
			verdict=1
		fi
	else
		say "FAIL the state after the reboot could not be recorded"
		verdict=1
	fi
	if ((verdict)); then
		say "RESULT: FAILED (report: $report)"
		return 1
	fi
	say "RESULT: PASSED (report: $report)"
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

main() {
	local cmd=${1:-}
	[[ -n $cmd ]] || {
		usage >&2
		exit 2
	}
	shift
	case $cmd in
	before) cmd_before "$@" ;;
	after) cmd_after "$@" ;;
	clean) rm -rf "$STATE_DIR" ;;
	compare)
		(($# == 2)) || die "compare takes two directories"
		compare "$@"
		;;
	judge)
		(($# == 1)) || die "judge takes one file"
		judge "$1"
		;;
	-h | --help | help) usage ;;
	*)
		usage >&2
		exit 2
		;;
	esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
	main "$@"
fi
