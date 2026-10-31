#!/usr/bin/env python3
"""Demonstrate that removing the submission cap fails the real SMTP invariant."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/concurrency/submissions.rs"
COMMAND = [
    "cargo", "test", "--locked", "--test", "concurrency_suite",
    "submissions::parallel_submissions_accept_exactly_the_account_limit",
    "--", "--exact", "--nocapture",
]


def run():
    result = subprocess.run(COMMAND, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    print(result.stdout, end="", flush=True)
    return result


def main():
    original = SOURCE.read_bytes()
    before = b".with_global_submission_rate_limit(Some(LIMIT as u32));"
    after = b".with_global_submission_rate_limit(None);"
    if original.count(before) != 1:
        raise SystemExit("Expected exactly one cap to remove; source left untouched")
    if run().returncode != 0:
        raise SystemExit("Baseline failed; no mutation applied")
    try:
        SOURCE.write_bytes(original.replace(before, after, 1))
        result = run()
        if result.returncode == 0:
            raise SystemExit("Mutation survived: the invariant failed to detect the missing cap")
        if ("exact account cap" not in result.stdout
                or "left: 64" not in result.stdout or "right: 7" not in result.stdout):
            raise SystemExit("Mutation failed for a different reason; sensitivity unproven")
        print("Missing cap detected: 64 accepted instead of 7", flush=True)
    finally:
        SOURCE.write_bytes(original)
        if SOURCE.read_bytes() != original:
            raise SystemExit("Failed to restore original source")
    if run().returncode != 0:
        raise SystemExit("Restored baseline failed")


if __name__ == "__main__":
    main()
