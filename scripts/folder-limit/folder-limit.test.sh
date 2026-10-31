#!/usr/bin/env bash
# Exercise the gate on real git indexes, plus the actual workflow's base loader.
set -euo pipefail
export LC_ALL=C

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/folder-limit.sh"
workflow="$here/../../.github/workflows/folder-limit.yml"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
passed=0
failed=0
exceptions=.github/folder-limit-exceptions.txt

new_repo() {
	local name="$1"
	mkdir -p "$tmp/$name"
	cd "$tmp/$name"
	git init -q
	git config user.email t@example.com
	git config user.name t
	git config commit.gpgsign false
	git config core.hooksPath /dev/null
	unset BASE
}

files() {
	local dir="$1" count="$2" i
	mkdir -p "$dir"
	for ((i = 1; i <= count; i++)); do : >"$dir/file $i"; done
	git add -- "$dir"
}

exception() {
	mkdir -p .github
	printf '%s\t%s\t%s\n' "$1" "$2" 'Fixture with a documented reason.' >"$exceptions"
	git add -- "$exceptions"
}

# Assert exit status AND a diagnostic row, so an unrelated shell failure cannot
# stand in for an intended refusal. Empty NEEDLE only checks the exit status.
expect() {
	local label="$1" want="$2" needle="$3" got=0 output
	shift 3
	if output="$("$@" 2>&1)"; then got=0; else got=$?; fi
	if [ "$got" -eq "$want" ] && { [ -z "$needle" ] || [[ "$output" == *"$needle"* ]]; }; then
		passed=$((passed + 1))
	else
		printf 'FAIL: %s (want status %d, got %d; need %q)\n%s\n' "$label" "$want" "$got" "$needle" "$output" >&2
		failed=$((failed + 1))
	fi
}

new_repo twenty
files leaf 20
expect '20 direct files' 0 'folder-limit: OK' bash "$script"
: >leaf/untracked
expect 'untracked file does not count' 0 'folder-limit: OK' bash "$script"
rm leaf/untracked
files leaf/child 20
expect 'child files are not counted in parent' 0 'folder-limit: OK' bash "$script"
files leaf 21
expect '21 without exception' 1 $'leaf\t21\t20\ttoo many direct files' bash "$script"
exception leaf 22
expect 'exception below ceiling' 0 'folder-limit: OK' bash "$script"
files leaf 22
expect 'exception at ceiling' 0 'folder-limit: OK' bash "$script"
files leaf 23
expect 'exception over ceiling' 1 $'leaf\t23\t22\ttoo many direct files' bash "$script"
git rm -qf -- 'leaf/file 23' 'leaf/file 22' 'leaf/file 21'
expect 'dead exception at 20' 1 $'leaf\t20\t22\tdead exception' bash "$script"
git rm -qf -- 'leaf/file 20'
expect 'dead exception below 20' 1 $'leaf\t19\t22\tdead exception' bash "$script"
git rm -qrf -- leaf
expect 'exception for removed folder' 1 $'leaf\t0\t22\tdead exception' bash "$script"

new_repo exclusions
files testdata 21
files testdata/deep 21
files auth/testdata/deep 21
files .github/workflows 21
expect 'testdata at any depth and flat workflows' 0 'folder-limit: OK' bash "$script"
files .github/workflows/nested 21
expect 'workflow exclusion applies only to flat folder' 1 $'.github/workflows/nested\t21\t20' bash "$script"
git rm -qrf -- .github/workflows/nested
files not-testdata 21
expect 'testdata exclusion matches a complete component' 1 $'not-testdata\t21\t20' bash "$script"

new_repo spaces
files 'folder with spaces' 20
expect 'spaces in folder and file names at limit' 0 'folder-limit: OK' bash "$script"
files 'folder with spaces' 21
expect 'spaces still count over limit' 1 $'folder\\ with\\ spaces\t21\t20' bash "$script"
exception 'folder with spaces' 21
expect 'exception with spaces' 0 'folder-limit: OK' bash "$script"

new_repo root
files . 21
expect 'root folder' 1 $'.\t21\t20' bash "$script"
exception . 21
expect 'root exception' 0 'folder-limit: OK' bash "$script"

new_repo ordered
files zebra 21
files alpha 22
expect 'offenders sorted by folder' 1 $'alpha\t22\t20\ttoo many direct files\nzebra\t21\t20' bash "$script"

new_repo format
files leaf 21
exception leaf 21
printf 'leaf\t22\tDuplicate\n' >>"$exceptions"
expect 'duplicate exception' 1 'duplicate exception' bash "$script"
printf 'leaf\t21\t\n' >"$exceptions"
expect 'missing reason' 1 'expected exactly three fields and a reason' bash "$script"
printf 'leaf 21 Reason\n' >"$exceptions"
expect 'spaces cannot replace tabs' 1 'expected path<TAB>ceiling<TAB>reason' bash "$script"
exception leaf 020
expect 'reject octal ceiling' 1 'ceiling must be a decimal integer' bash "$script"
exception leaf 20
expect 'exception ceiling must exceed default' 1 'ceiling must be a decimal integer' bash "$script"
exception ./leaf 21
expect 'reject noncanonical exception path' 1 'use a relative folder' bash "$script"
exception leaf/ 21
expect 'reject trailing slash alias' 1 'use a relative folder' bash "$script"
exception leaf 21
printf '# Comment\n\n' >>"$exceptions"
expect 'comments and blank lines' 0 'folder-limit: OK' bash "$script"
printf 'leaf\t21\tReason without final newline' >"$exceptions"
expect 'last line without newline' 0 'folder-limit: OK' bash "$script"

new_repo ratchet
files leaf 21
exception leaf 22
git commit -qm base
base="$(git rev-parse HEAD)"
expect 'unchanged ceiling' 0 'folder-limit: OK' env BASE="$base" bash "$script"
exception leaf 23
expect 'ceiling cannot increase' 1 $'leaf\t21\t23\tceiling increased from 22' env BASE="$base" bash "$script"
exception leaf 21
expect 'ceiling can decrease' 0 'folder-limit: OK' env BASE="$base" bash "$script"
expect 'unreadable base is an error' 128 '' env BASE=deadbeef bash "$script"

# Extract and execute the real workflow loader, rather than copying its logic.
awk '
	/^          set -euo pipefail$/ { block=1 }
	block && /^          / { sub(/^          /, ""); print; next }
	block { exit }
' "$workflow" >"$tmp/loader.sh"
if [ ! -s "$tmp/loader.sh" ]; then
	echo 'FAIL: no base loader found in folder-limit workflow' >&2
	exit 1
fi
new_repo loader
files leaf 21
git commit -qm 'base before gate'
first_base="$(git rev-parse HEAD)"
mkdir -p scripts/folder-limit "$tmp/runner"
cp "$script" scripts/folder-limit/folder-limit.sh
expect 'first introduction uses PR gate and rejects 21' 1 $'leaf\t21\t20' \
	env BASE="$first_base" RUNNER_TEMP="$tmp/runner" bash "$tmp/loader.sh"
exception leaf 21
expect 'first introduction with written exception' 0 'folder-limit: OK' \
	env BASE="$first_base" RUNNER_TEMP="$tmp/runner" bash "$tmp/loader.sh"
git add scripts .github
git commit -qm 'trusted base gate'
trusted_base="$(git rev-parse HEAD)"
# A PR replaces its checker with a successful no-op and grows the folder.
printf '#!/usr/bin/env bash\nexit 0\n' >scripts/folder-limit/folder-limit.sh
files leaf 22
expect 'PR cannot replace trusted base checker' 1 $'leaf\t22\t21' \
	env BASE="$trusted_base" RUNNER_TEMP="$tmp/runner" bash "$tmp/loader.sh"
exception leaf 22
expect 'PR cannot raise trusted base ceiling' 1 'ceiling increased from 21' \
	env BASE="$trusted_base" RUNNER_TEMP="$tmp/runner" bash "$tmp/loader.sh"
expect 'invalid base never falls back to PR no-op' 128 '' \
	env BASE=deadbeef RUNNER_TEMP="$tmp/runner" bash "$tmp/loader.sh"

printf 'passed %d, failed %d\n' "$passed" "$failed"
if [ "$failed" -ne 0 ]; then exit 1; fi
