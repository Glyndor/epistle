import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest

import fuzz_targets as ft
from version_bump.fixtures import Repo, bump_all

FUZZ_CRATE = os.path.join(os.path.dirname(__file__), "..", "..", "fuzz")
FUZZ_DIR = os.path.join(FUZZ_CRATE, "fuzz_targets")


def declared_targets():
    """The [[bin]] entries of the fuzz crate: a target can span several
    files, so the manifest is the list, not the files on disk."""
    with open(os.path.join(FUZZ_CRATE, "Cargo.toml"), "rb") as manifest:
        return tomllib.load(manifest)["bin"]


class SelectTests(unittest.TestCase):
    def test_every_target_in_the_fuzz_crate_is_listed(self):
        declared = sorted(b["name"] for b in declared_targets())
        self.assertEqual(sorted(ft.ALL), declared)

    def test_every_declared_target_has_its_source(self):
        for target in declared_targets():
            with self.subTest(target=target["name"]):
                path = os.path.join(FUZZ_CRATE, target["path"])
                self.assertTrue(os.path.isfile(path), path)

    def test_every_target_source_is_declared(self):
        # A file that starts a target and is missing from the manifest is
        # never built; a module of a target does not start one.
        declared = {os.path.normpath(b["path"]) for b in declared_targets()}
        root = os.path.join(FUZZ_CRATE, "fuzz_targets")
        for folder, _, names in os.walk(root):
            for name in names:
                path = os.path.join(folder, name)
                with open(path, encoding="utf-8") as source:
                    if "fuzz_target!" not in source.read():
                        continue
                relative = os.path.normpath(os.path.relpath(path, FUZZ_CRATE))
                self.assertIn(relative, declared)

    def test_every_mapped_target_exists(self):
        for targets in ft.FOLDERS.values():
            for target in targets:
                self.assertIn(target, ft.ALL)

    def test_schedule_and_dispatch_run_everything(self):
        self.assertEqual(ft.select("schedule", ["src/imap/x.rs"]), ft.ALL)
        self.assertEqual(ft.select("workflow_dispatch", []), ft.ALL)

    def test_one_protocol_runs_only_its_targets(self):
        self.assertEqual(
            ft.select("pull_request", ["src/imap/session/mod.rs"]),
            ["imap_command", "imap_session", "mime", "migrate_imap_response"],
        )
        self.assertEqual(
            ft.select("pull_request", ["src/smtp/a.rs", "src/smtp/b/c.rs"]),
            ["smtp_command", "smtp_session", "smtp_line", "smtp_address", "smtp_data"],
        )

    def test_the_parsers_of_one_folder_run_their_own_target(self):
        for path, target in (
            ("src/antispam/attachments/sniff/mod.rs", "attachment_inspect"),
            ("src/arc/signature.rs", "arc_headers"),
            ("src/jwt/mod.rs", "jwt_decode"),
            ("src/queue/client/conn/mod.rs", "smtp_reply"),
            ("src/mtasts/policy/mod.rs", "dns_security_records"),
            ("src/rules/mod.rs", "rules_match"),
            ("src/migrate/imap/parse/mod.rs", "migrate_imap_response"),
            ("src/cli/backup/tar_format/mod.rs", "backup_tar"),
            ("src/antispam/arf/mod.rs", "arf_report"),
        ):
            self.assertEqual(ft.select("pull_request", [path]), [target])

    def test_the_webdav_folder_runs_both_webdav_targets(self):
        self.assertEqual(
            ft.select("pull_request", ["src/webdav/rrule/mod.rs"]),
            ["webdav_filter_rrule", "webdav_report_body"],
        )

    def test_the_account_directory_runs_the_imap_session(self):
        got = ft.select("pull_request", ["src/smtp/directory/bans.rs"])
        self.assertIn("imap_session", got)
        self.assertIn("smtp_command", got)
        self.assertNotIn(
            "imap_session", ft.select("pull_request", ["src/smtp/session/mod.rs"])
        )

    def test_two_protocols_run_both(self):
        got = ft.select("pull_request", ["src/pop3/a.rs", "src/dkim/b.rs"])
        self.assertEqual(got, ["pop3_command", "pop3_session", "dkim_signature", "mime"])

    def test_the_pop3_session_target_runs_with_the_pop3_source(self):
        self.assertEqual(
            ft.select("pull_request", ["src/pop3/session/mod.rs"]),
            ["pop3_command", "pop3_session"],
        )

    def test_anything_unmapped_runs_everything(self):
        for path in (
            "src/util/header/mod.rs",
            "src/lib.rs",
            "src/fuzzing.rs",
            "Cargo.toml",
            "migrations/0009_new.sql",
            ".sqlx/query-1.json",
            "deploy/images/Dockerfile",
            "build.rs",
            "fuzz/Cargo.lock",
            "fuzz/fuzz_targets/message/mime.rs",
            ".github/workflows/fuzz.yml",
            ".github/scripts/fuzz_targets.py",
            "a-file-nobody-has-seen-yet",
        ):
            self.assertEqual(ft.select("pull_request", [path, "src/imap/a.rs"]), ft.ALL)

    def test_documentation_alone_runs_nothing(self):
        self.assertEqual(ft.select("pull_request", ["docs/limits.md", "README.md"]), [])

    def test_what_the_fuzz_crate_does_not_build_runs_nothing(self):
        unrelated = [
            "Cargo.lock",
            "tests/smtp/hostile_smtp.rs",
            "benches/parsers.rs",
            "examples/profile.rs",
            "debian/changelog",
            ".github/workflows/db.yml",
            ".github/scripts/sign.py",
        ]
        self.assertEqual(ft.select("pull_request", unrelated), [])
        self.assertEqual(
            ft.select("pull_request", unrelated + ["src/pop3/a.rs"]),
            ft.select("pull_request", ["src/pop3/a.rs"]),
        )
        self.assertNotEqual(ft.select("pull_request", ["src/pop3/a.rs"]), ft.ALL)

    def test_the_folders_that_only_mime_reads_run_mime(self):
        self.assertEqual(ft.select("pull_request", ["src/dmarc/author/mod.rs"]), ["mime"])
        self.assertEqual(ft.select("pull_request", ["src/api/jmap/email/mod.rs"]), ["mime"])

    def test_the_store_of_managesieve_runs_the_validator(self):
        self.assertIn(
            "sieve_validate", ft.select("pull_request", ["src/managesieve/store/mod.rs"])
        )

    def test_the_reports_folder_runs_the_payload_and_the_report_walker(self):
        # `mime` calls reports::mime::find_report_part and reports::Kind, so
        # the whole folder runs both rather than a split that could miss one.
        for path in ("src/reports/dmarc/mod.rs", "src/reports/mime/mod.rs"):
            self.assertEqual(ft.select("pull_request", [path]), ["mime", "report_payload"])

    def test_no_changed_paths_runs_everything(self):
        self.assertEqual(ft.select("pull_request", []), ft.ALL)


ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
MODULE = r"((?:[a-z0-9_]+::)*[a-z0-9_]+)"


def target_source(target):
    """The source of a target: its file, or every file of its folder when the
    manifest points at a main.rs."""
    for entry in declared_targets():
        if entry["name"] != target:
            continue
        path = os.path.join(FUZZ_CRATE, entry["path"])
        if os.path.basename(path) == "main.rs":
            files = sorted(
                os.path.join(folder, name)
                for folder, _, names in os.walk(os.path.dirname(path))
                for name in names
                if name.endswith(".rs")
            )
        else:
            files = [path]
        text = []
        for name in files:
            with open(name, encoding="utf-8") as handle:
                text.append(handle.read())
        return "\n".join(text)
    raise AssertionError(f"no source for {target}")


def entry_point(name):
    """The body of `pub fn <name>` in src/fuzzing.rs."""
    with open(os.path.join(ROOT, "src", "fuzzing.rs"), encoding="utf-8") as handle:
        text = handle.read()
    found = re.search(rf"^pub fn {name}\(.*?^}}$", text, re.S | re.M)
    if not found:
        raise AssertionError(f"src/fuzzing.rs has no `pub fn {name}`")
    return found.group(0)


def modules_reached(target):
    """Module paths a target calls directly: `epistle::a::b` in its own file,
    and `crate::a::b` in the src/fuzzing.rs entry point it goes through."""
    text = target_source(target)
    reached = set()
    for name in re.findall(r"epistle::fuzzing::(\w+)", text):
        reached |= set(re.findall(rf"crate::{MODULE}", entry_point(name)))
    for module in re.findall(rf"epistle::{MODULE}", text):
        if module.split("::")[0] != "fuzzing":
            reached.add(module)
    return reached


class MapAgreesWithTheTargetsTests(unittest.TestCase):
    """A change to a module a target calls must select that target.

    The map is written by hand, and it had drifted: `sieve_validate` calls
    the ManageSieve script store and `mime` calls the report walker, and a
    pull request in either folder ran neither. This reads the targets and
    the entry points and asks the selection itself, so a new call that the
    map misses fails here. It sees direct calls only, not what those
    modules call in turn.
    """

    def test_every_target_reaches_something(self):
        for target in ft.ALL:
            self.assertTrue(modules_reached(target), f"{target} calls no epistle module")

    def test_a_change_to_a_called_module_selects_the_target(self):
        for target in ft.ALL:
            for module in sorted(modules_reached(target)):
                path = "src/" + module.replace("::", "/") + "/mod.rs"
                self.assertIn(
                    target,
                    ft.select("pull_request", [path]),
                    f"{target} calls {module}, but a change to {path} does not run it",
                )


class VersionBumpTests(unittest.TestCase):
    """A version bump runs no target, and only the base's judge can say so."""

    def plan(self, judge, change=bump_all):
        repo = Repo(change, judge=judge)
        self.addCleanup(repo.close)
        with tempfile.NamedTemporaryFile("r", suffix=".out") as output:
            env = {
                **os.environ,
                "EVENT_NAME": "pull_request",
                "BASE_SHA": "base",
                "HEAD_SHA": "head",
                "GITHUB_OUTPUT": output.name,
            }
            done = subprocess.run(
                [sys.executable, os.path.abspath(ft.__file__)],
                cwd=repo.dir,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(done.returncode, 0, done.stderr)
            return output.read()

    def test_a_bump_runs_no_target(self):
        self.assertEqual(self.plan(judge=True), "targets=[]\n")

    def test_a_base_without_the_judge_chooses_as_usual(self):
        # Cargo.toml is not narrowed, so without the judge everything runs.
        self.assertEqual(self.plan(judge=False), f"targets={json.dumps(ft.ALL)}\n")

    def test_a_bump_with_a_source_change_is_not_a_bump(self):
        def change():
            bump_all()
            os.makedirs("src/pop3", exist_ok=True)
            with open("src/pop3/a.rs", "w", encoding="utf-8") as handle:
                handle.write("// touched\n")

        self.assertEqual(self.plan(judge=True, change=change), f"targets={json.dumps(ft.ALL)}\n")

    def test_an_unreadable_base_is_not_a_bump(self):
        self.assertFalse(ft.version_bump("deadbeef" * 5, "HEAD"))


if __name__ == "__main__":
    unittest.main()
