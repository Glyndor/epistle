#!/usr/bin/env bash
#
# Two attacks on the secret scan, kept apart from the tests that are copied from the shared
# version of the check so that updating that version cannot drop them. The credential-shaped
# string is assembled at run time, so this file does not trip the check it tests.
#
#   a. A file with a NUL and a byte that is not UTF-8 that sorts before a file with a token:
#      the scan must still fail, in any locale, whatever grep makes of the stream.
#   b. A branch with no common history, merged: its root commit adds a token and its second
#      commit removes it. A commit with no parent is compared with the empty tree, so the
#      token is found although the net diff of the merge does not hold it.
#
# SECRET_SCAN=<path> runs the same attacks against another copy of the check.
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${SECRET_SCAN:-$HERE/check-secrets.sh}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0

check() { # <desc> <want> <got>
	if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok    $1"
	else fail=$((fail + 1)); echo "FAIL  $1 (want '$2', got '$3')"; fi
}

token="gh$(printf 'p')_$(printf '%*s' 36 '' | tr ' ' A)"
repo="$WORK/repo"
git init -q -b main "$repo"
gitc() { git -C "$repo" -c user.name=t -c user.email=t@x -c commit.gpgSign=false "$@"; }
echo base > "$repo/README"; gitc add -A; gitc commit -q -m base
base="$(git -C "$repo" rev-parse HEAD)"

scan() { # <head> [locale]: status and output of the scan of base..head
	out="$(cd "$repo" && LC_ALL="${2:-}" bash "$SCRIPT" "$base" "$1" 2>&1)"; rc=$?
}

# a. The noise sorts before the token: 0-... < 1-... < z-...
gitc checkout -q -b noise
printf 'a\000b\377\376\n' > "$repo/0-binary.bin"
printf 'x\377y\n' > "$repo/1-latin1.txt"
printf 'k = %s\n' "$token" > "$repo/z-token.txt"
gitc add -A; gitc commit -q -m noise
for locale in "" C C.UTF-8 en_US.UTF-8 es_ES.UTF-8; do
	scan noise "$locale"
	check "a: NUL and 0xFF before a token do not hide it (locale '${locale:-unset}')" "1 1 0" \
		"$rc $(printf '%s' "$out" | grep -c 'z-token.txt:1 GitHub token') $(printf '%s' "$out" | grep -cF "$token")"
done
check "a: the scan reads bytes, whatever the locale of the runner" 1 "$(grep -c '^export LC_ALL=C$' "$SCRIPT")"

# a2. The token is inside the file that holds the NUL.
gitc checkout -q -b inside main
printf 'k = %s\n\000\377' "$token" > "$repo/logo.png"
gitc add -A; gitc commit -q -m inside
scan inside
check "a: a token in a file that also holds a NUL is found" "1 1" "$rc $(printf '%s' "$out" | grep -c 'logo.png:1 GitHub token')"

# b. A branch with no common history, whose root adds the token and whose second commit removes it.
gitc checkout -q --orphan unrelated
gitc rm -rfq . >/dev/null 2>&1 || true
printf 'k = %s\n' "$token" > "$repo/t.txt"; gitc add t.txt; gitc commit -q -m root
gitc rm -q t.txt; echo fine > "$repo/ok.txt"; gitc add ok.txt; gitc commit -q -m second
gitc checkout -q -b merged main
gitc merge -q --allow-unrelated-histories --no-ff unrelated -m "merge unrelated"
check "b: the merge holds no token in its tree" 0 "$(git -C "$repo" grep -cF "$token" merged -- 2>/dev/null | awk -F: '{ n += $NF } END { print n + 0 }')"
scan merged
check "b: a token added by a root commit and removed by the next fails" "1 1" "$rc $(printf '%s' "$out" | grep -c 't.txt:1 GitHub token')"
check "b: and is not printed" 0 "$(printf '%s' "$out" | grep -cF "$token")"

# b2. The same history without the merge: the branch alone, against the base with no merge base.
scan unrelated
check "b: the unrelated branch on its own fails too, or stops with an error and never says clean" 0 \
	"$(printf '%s' "$out" | grep -c 'no credential-shaped lines added')"

echo "$pass passed, $fail failed"
echo "DONE $(basename "$0") $pass $fail"
[ "$fail" -eq 0 ]
