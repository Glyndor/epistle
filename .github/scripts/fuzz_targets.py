#!/usr/bin/env python3
"""Pick the cargo-fuzz targets a pull request has to run.

A pull request that only touches the source of one protocol needs that
protocol's targets, not all twenty-two: every target is a separate job that
installs a nightly toolchain and builds the crate. Anything this script does
not know how to narrow runs every target: a change outside the mapped folders
(shared code, the manifest, the fuzz crate, this workflow) can reach any of
them. Scheduled and manual runs always run every target.
"""

import json
import os
import subprocess
import sys

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
]

# Folder of the source -> the targets that exercise it and nothing else.
FOLDERS = {
    "src/smtp/": ["smtp_command", "smtp_line", "smtp_address", "smtp_data"],
    "src/imap/": ["imap_command", "mime"],
    "src/sieve/": ["sieve_message", "sieve_script", "sieve_run", "sieve_validate"],
    "src/pop3/": ["pop3_command", "pop3_session"],
    "src/managesieve/": ["managesieve_command"],
    "src/dkim/": ["dkim_signature", "mime"],
    "src/antispam/attachments/": ["attachment_inspect"],
    "src/webdav/": ["webdav_filter_rrule"],
    "src/arc/": ["arc_headers"],
    "src/jwt/": ["jwt_decode"],
    "src/queue/client/": ["smtp_reply"],
    "src/mtasts/": ["dns_security_records"],
    "src/tlsrpt/": ["dns_security_records", "report_payload"],
    "src/dane/": ["dns_security_records"],
    "src/reports/": ["report_payload"],
    "src/rules/": ["rules_match"],
}

# Files under src that the fuzz entry points go through directly.
SHARED = ("src/fuzzing.rs",)


def select(event, changed):
    """Targets to run for `event` given the list of changed paths."""
    if event != "pull_request" or not changed:
        return list(ALL)
    chosen = set()
    for path in changed:
        if path in SHARED or not path.startswith("src/"):
            if path.startswith("docs/") or path.endswith(".md"):
                continue
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


def main():
    event = os.environ.get("EVENT_NAME", "")
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
