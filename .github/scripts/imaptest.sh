#!/usr/bin/env bash
# Run Dovecot's imaptest scripted tests against an epistle server built from
# this tree. Used by .github/workflows/imaptest.yml and runnable locally:
#
#   .github/scripts/imaptest.sh <epistle binary> <imaptest source dir>
#
# IMAPTEST_IMAGE names the imaptest image (pinned by digest in the workflow),
# CONTAINER the engine (docker or podman), IMAPTEST_ONLY a space-separated
# subset of scripts to run. Every script under
# <source>/src/tests runs except the ones in SKIP below, each with a reason.
# The run fails on any script that fails, and the summary lists them.
set -euo pipefail

bin=$(realpath "$1")
source_dir=$(realpath "$2")
image=${IMAPTEST_IMAGE:?set IMAPTEST_IMAGE}
engine=${CONTAINER:-docker}
port=${IMAPTEST_PORT:-4993}
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
mbox="$repo/tests/fixtures/imaptest.mbox"

# Scripts that test something epistle does not offer, by name. Each line says
# why; a script leaves this list as soon as the feature exists.
declare -A SKIP=()

# Scripts that fail today, each with the reason. They still run: a known
# failure is reported and does not fail the job, and a listed script that
# passes fails the job until it is taken off this list, so the list only
# shrinks and every other script is held to passing.
declare -A KNOWN_FAILING=(
	[search-flags]="no message is ever \\Recent (zero-recent policy), so RECENT, NEW and OLD differ"
	[copy]="\\Recent is not tracked: epistle reports zero recent messages"
	[select]="\\Recent is not tracked: epistle reports zero recent messages"
	[mutf7]="mailbox names: hierarchy and characters the store refuses"
	[subscribe]="mailbox names: hierarchy and characters the store refuses"
	[list]="mailbox names: hierarchy and characters the store refuses"
	[listext]="mailbox names: hierarchy and characters the store refuses"
	[fetch-binary-mime]="FETCH ENVELOPE, BINARY and STATUS replies differ"
	[append-binary]="FETCH ENVELOPE, BINARY and STATUS replies differ"
	[uidvalidity]="FETCH ENVELOPE, BINARY and STATUS replies differ"
	[broken]="FETCH ENVELOPE, BINARY and STATUS replies differ"
	[fetch-body-message-rfc822-mime]="FETCH ENVELOPE, BINARY and STATUS replies differ"
	[notify]="ID line limit; NOTIFY SET STATUS syntax"
)

work=$(mktemp -d)
server_pid=""
cleanup() {
	if [ -n "$server_pid" ]; then
		kill "$server_pid" 2>/dev/null || true
		wait "$server_pid" 2>/dev/null || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT

password=$(openssl rand -hex 16)
if [ -n "${GITHUB_ACTIONS:-}" ]; then
	echo "::add-mask::$password"
fi

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/key.pem" -out "$work/cert.pem" \
	-days 2 -subj "/CN=mail.epistle.test" \
	-addext "subjectAltName=DNS:mail.epistle.test,IP:127.0.0.1" 2>/dev/null
mkdir -p "$work/data"
cat >"$work/epistle.toml" <<CONF
hostname = "mail.epistle.test"
data_dir = "$work/data"
domains = ["epistle.test"]

[tls]
cert_file = "$work/cert.pem"
key_file = "$work/key.pem"

[[listeners]]
kind = "imaps"
addr = "127.0.0.1"
port = $port
CONF
chmod 600 "$work/epistle.toml"
printf '%s' "$password" | "$bin" account add --config "$work/epistle.toml" \
	--address tester@epistle.test tester >/dev/null

"$bin" serve --config "$work/epistle.toml" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 100); do
	if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
		break
	fi
	sleep 0.1
done

run_imaptest() {
	"$engine" run --rm --network host \
		-v "$source_dir/src/tests:/tests:ro" -v "$mbox:/imaptest.mbox:ro" \
		"$image" host=127.0.0.1 port="$port" ssl=any-cert \
		user=tester@epistle.test pass="$password" mbox=/imaptest.mbox "$@"
}

failed=()
for path in "$source_dir"/src/tests/*; do
	name=$(basename "$path")
	case "$name" in *.mbox) continue ;; esac
	if [ -n "${IMAPTEST_ONLY:-}" ] && [[ " $IMAPTEST_ONLY " != *" $name "* ]]; then
		continue
	fi
	if [ -n "${SKIP[$name]:-}" ]; then
		echo "skip $name: ${SKIP[$name]}"
		continue
	fi
	passed=false
	if output=$(run_imaptest test="/tests/$name" 2>&1) && ! grep -qE '[1-9][0-9]* failed' <<<"$output"; then
		passed=true
	fi
	known=${KNOWN_FAILING[$name]:-}
	if $passed && [ -z "$known" ]; then
		echo "pass $name"
	elif $passed; then
		echo "FAIL $name: passes now, take it off KNOWN_FAILING"
		failed+=("$name")
	elif [ -n "$known" ]; then
		echo "known $name: $known"
	else
		echo "FAIL $name"
		tail -40 <<<"$output"
		failed+=("$name")
	fi
done

if [ "${#failed[@]}" -gt 0 ]; then
	echo "imaptest: ${#failed[@]} script(s) failed: ${failed[*]}"
	echo "server log tail:"
	tail -30 "$work/server.log"
	exit 1
fi
echo "imaptest: no unexpected result (${#KNOWN_FAILING[@]} known failures listed)"
