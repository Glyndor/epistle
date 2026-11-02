import os
import unittest

import fuzz_targets as ft

FUZZ_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "fuzz", "fuzz_targets")


class SelectTests(unittest.TestCase):
    def test_every_target_in_the_fuzz_crate_is_listed(self):
        on_disk = sorted(
            n[:-3]
            for _, _, names in os.walk(FUZZ_DIR)
            for n in names
            if n.endswith(".rs")
        )
        self.assertEqual(sorted(ft.ALL), on_disk)

    def test_every_mapped_target_exists(self):
        for targets in ft.FOLDERS.values():
            for target in targets:
                self.assertIn(target, ft.ALL)

    def test_schedule_and_dispatch_run_everything(self):
        self.assertEqual(ft.select("schedule", ["src/imap/x.rs"]), ft.ALL)
        self.assertEqual(ft.select("workflow_dispatch", []), ft.ALL)

    def test_one_protocol_runs_only_its_targets(self):
        self.assertEqual(
            ft.select("pull_request", ["src/imap/session/mod.rs"]), ["imap_command", "mime"]
        )
        self.assertEqual(
            ft.select("pull_request", ["src/smtp/a.rs", "src/smtp/b/c.rs"]),
            ["smtp_command", "smtp_line", "smtp_address", "smtp_data"],
        )

    def test_the_parsers_of_one_folder_run_their_own_target(self):
        for path, target in (
            ("src/antispam/attachments/sniff/mod.rs", "attachment_inspect"),
            ("src/webdav/rrule/mod.rs", "webdav_filter_rrule"),
            ("src/arc/signature.rs", "arc_headers"),
            ("src/jwt/mod.rs", "jwt_decode"),
            ("src/queue/client/conn/mod.rs", "smtp_reply"),
            ("src/mtasts/policy/mod.rs", "dns_security_records"),
            ("src/reports/dmarc/mod.rs", "report_payload"),
            ("src/rules/mod.rs", "rules_match"),
        ):
            self.assertEqual(ft.select("pull_request", [path]), [target])

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
            "Cargo.lock",
            "fuzz/fuzz_targets/message/mime.rs",
            ".github/workflows/fuzz.yml",
        ):
            self.assertEqual(ft.select("pull_request", [path, "src/imap/a.rs"]), ft.ALL)

    def test_documentation_alone_runs_nothing(self):
        self.assertEqual(ft.select("pull_request", ["docs/limits.md", "README.md"]), [])

    def test_no_changed_paths_runs_everything(self):
        self.assertEqual(ft.select("pull_request", []), ft.ALL)


if __name__ == "__main__":
    unittest.main()
