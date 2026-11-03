#!/usr/bin/env python3
"""Pick the cargo-fuzz targets a pull request has to run.

A pull request that only touches the source of one protocol needs that
protocol's targets, not every one of them: every target is a separate job that
installs a nightly toolchain and builds the crate. Anything this script does
not know how to narrow runs every target: a change outside the mapped folders
(shared code, the manifest, the fuzz crate, this workflow) can reach any of
them. A pull request that is only a version bump runs none, and only when the
copy of the judge in the base commit says so. Scheduled and manual runs
always run every target.
"""

import json
import os
import subprocess
import sys
import tempfile

ALL = [
    "smtp_command",
    "smtp_line",
    "smtp_address",
    "imap_command",
    "sieve_message",
    "sieve_script",
    "sieve_run",
    "sieve_validate",
    "pop3_command",
    "pop3_session",
    "managesieve_command",
    "smtp_data",
    "dkim_signature",
    "mime",
    "attachment_inspect",
    "webdav_filter_rrule",
    "arc_headers",
    "jwt_decode",
    "smtp_reply",
    "dns_security_records",
    "report_payload",
    "rules_match",
    "migrate_imap_response",
]

# Folder of the source -> the targets that exercise it and nothing else.
FOLDERS = {
    "src/smtp/": ["smtp_command", "smtp_line", "smtp_address", "smtp_data"],
    "src/imap/": ["imap_command", "mime", "migrate_imap_response"],
    "src/sieve/": ["sieve_message", "sieve_script", "sieve_run", "sieve_validate"],
    "src/pop3/": ["pop3_command", "pop3_session"],
    "src/managesieve/": ["managesieve_command", "sieve_validate"],
    "src/dkim/": ["dkim_signature", "mime"],
    "src/dmarc/": ["mime"],
    "src/api/jmap/": ["mime"],
    "src/antispam/attachments/": ["attachment_inspect"],
    "src/webdav/": ["webdav_filter_rrule"],
    "src/arc/": ["arc_headers"],
    "src/jwt/": ["jwt_decode"],
    "src/queue/client/": ["smtp_reply"],
    "src/mtasts/": ["dns_security_records"],
    "src/tlsrpt/": ["dns_security_records", "report_payload"],
    "src/dane/": ["dns_security_records"],
    "src/reports/": ["report_payload", "mime"],
    "src/rules/": ["rules_match"],
    "src/migrate/imap/": ["migrate_imap_response"],
}

# Files under src that the fuzz entry points go through directly.
SHARED = ("src/fuzzing.rs",)

# Paths outside src that cannot change what a target builds or runs. The fuzz
# crate is a workspace of its own with its own lockfile (fuzz/Cargo.lock), so
# the root Cargo.lock never reaches it, and it links the library only: the
# integration tests, benches, examples, packaging and the other workflows are
# not part of it. Cargo.toml is not here, because its features and dependency
# requirements do reach the library; nor are migrations/, .sqlx/ and deploy/,
# which the library embeds at build time.
UNRELATED_FILES = ("Cargo.lock",)
UNRELATED_FOLDERS = ("docs/", "tests/", "benches/", "examples/", "debian/", ".github/")

# The files of this workflow, which do change what runs.
OWN = (".github/workflows/fuzz.yml", ".github/scripts/fuzz_targets.py")

# The version bump judge, which `version_bump` reads from the base commit.
JUDGE = ".github/scripts/version_bump/is_version_bump.py"


def unrelated(path):
    """True for a path outside src that no fuzz target builds or runs."""
    if path in OWN:
        return False
    return (
        path in UNRELATED_FILES
        or path.endswith(".md")
        or path.startswith(UNRELATED_FOLDERS)
    )


def select(event, changed):
    """Targets to run for `event` given the list of changed paths."""
    if event != "pull_request" or not changed:
        return list(ALL)
    chosen = set()
    for path in changed:
        if unrelated(path):
            continue
        if path in SHARED or not path.startswith("src/"):
            return list(ALL)
        for folder, targets in FOLDERS.items():
            if path.startswith(folder):
                chosen.update(targets)
                break
        else:
            return list(ALL)
    return [target for target in ALL if target in chosen]


def changed_paths(base, head):
    out = subprocess.check_output(
        ["git", "diff", "--name-only", "-z", f"{base}...{head}"]
    )
    return [path for path in out.decode().split("\0") if path]


def version_bump(base, head):
    """True only when the judge stored in the base commit calls it a bump.

    The judge is not read from this checkout, so a pull request cannot edit
    it to skip its own targets. A base without the judge, or any failure to
    read or run it, answers False and the targets are chosen as usual.
    """
    try:
        script = subprocess.run(
            ["git", "show", f"{base}:{JUDGE}"], capture_output=True, check=True
        ).stdout
        with tempfile.NamedTemporaryFile(suffix=".py") as handle:
            handle.write(script)
            handle.flush()
            done = subprocess.run([sys.executable, "-I", handle.name, base, head], check=False)
    except (OSError, subprocess.CalledProcessError):
        return False
    return done.returncode == 0


def main():
    event = os.environ.get("EVENT_NAME", "")
    if event == "pull_request" and version_bump(os.environ["BASE_SHA"], os.environ["HEAD_SHA"]):
        targets = []
    else:
        changed = []
        if event == "pull_request":
            changed = changed_paths(os.environ["BASE_SHA"], os.environ["HEAD_SHA"])
        targets = select(event, changed)
    line = json.dumps(targets)
    print(line)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"targets={line}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
