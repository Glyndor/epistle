"""Who holds what in release.yml: the jobs that run dependency code hold nothing, and the key has one step."""

import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import ci_yaml

HERE = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/release.yml"
SCRIPTS_ONLY = ("attest", "sign", "verify-signatures", "image-manifest", "image-promote")
PUBLISHING = ("attest", "sign", "verify-signatures", "publish", "image-build", "image-manifest", "image-promote")
KEY = "secrets.GLYNDOR_RELEASE_ED25519_KEY"


def workflow():
    return ci_yaml.load(WORKFLOW)


def jobs():
    return workflow()["jobs"]


class Authority(unittest.TestCase):
    def test_each_job_holds_exactly_these_permissions(self):
        self.assertEqual({name: job.get("permissions") for name, job in jobs().items()}, {
            "verify": {"contents": "read"},
            "build-deb": {"contents": "read"},
            "build": {"contents": "read"},
            "attest": {"contents": "read", "id-token": "write", "attestations": "write"},
            "sign": {"contents": "read"},
            "sign-rehearsal": {"contents": "read"},
            "verify-signatures": {"contents": "read"},
            "publish": {"contents": "write"},
            "image-build": {"contents": "read", "packages": "write"},
            "image-promote": {"contents": "read", "packages": "write"},
            "image-manifest": {"contents": "read", "packages": "write", "id-token": "write", "attestations": "write"},
        })
        self.assertEqual(workflow()["permissions"], {})

    def test_the_jobs_that_compile_hold_neither_the_oidc_token_nor_an_attestation_nor_a_secret(self):
        for name in ("build-deb", "build"):
            text = str(jobs()[name])
            for forbidden in ("id-token", "attestations", "secrets.", "attest-build-provenance"):
                self.assertNotIn(forbidden, text, name)
            self.assertEqual(set(jobs()[name]["permissions"]), {"contents"}, name)
            self.assertEqual(jobs()[name]["permissions"]["contents"], "read", name)

    def test_the_attestation_job_runs_nothing_that_was_built(self):
        steps = jobs()["attest"]["steps"]
        runs = " ".join(step.get("run", "") for step in steps)
        for forbidden in ("cargo", "pip install", "dpkg-buildpackage", "make", "npm", "bun"):
            self.assertNotIn(forbidden, runs)
        for step in steps:
            self.assertNotIn("merge-multiple", str(step))

    def test_every_job_that_publishes_or_signs_is_in_the_release_environment(self):
        for name in PUBLISHING:
            self.assertEqual(jobs()[name].get("environment"), "release", name)
        for name in ("verify", "build-deb", "build", "sign-rehearsal"):
            self.assertNotIn("environment", jobs()[name], name)

    def test_the_jobs_with_authority_check_the_event_and_the_ref_in_shell_too(self):
        for name in ("attest", "sign", "verify-signatures", "publish"):
            first = jobs()[name]["steps"][0]["run"]
            self.assertIn("push:refs/tags/v*", first, name)
            self.assertIn("workflow_dispatch:refs/heads/main", first, name)
            self.assertIn("exit 1", first, name)

    def test_a_rehearsal_gets_no_permission_to_publish_and_no_secret(self):
        for name in PUBLISHING:
            if name not in ("image-manifest", "image-promote"):
                self.assertIn("!inputs.dry-run", jobs()[name]["if"], name)
        # The manifest and promotion jobs only run after the image jobs, which a rehearsal skips.
        self.assertIn("image-build", jobs()["image-manifest"]["needs"])
        self.assertIn("needs.image-build.result == 'success'", jobs()["image-manifest"]["if"])
        self.assertIn("image-manifest", jobs()["image-promote"]["needs"])
        self.assertIn("needs.image-manifest.result == 'success'", jobs()["image-promote"]["if"])
        self.assertNotIn("secrets.", str(jobs()["sign-rehearsal"]))
        self.assertEqual(jobs()["sign-rehearsal"]["permissions"], {"contents": "read"})
        self.assertIn("inputs.dry-run", jobs()["sign-rehearsal"]["if"])


class TheKey(unittest.TestCase):
    def test_the_key_is_read_in_one_step_of_one_job_and_that_step_only_signs(self):
        found = [(name, step) for name, job in jobs().items() for step in job.get("steps", []) if KEY in str(step)]
        self.assertEqual([name for name, _ in found], ["sign"])
        step = found[0][1]
        self.assertEqual(step["env"], {"GLYNDOR_RELEASE_ED25519_KEY": "${{ " + KEY + " }}"})
        self.assertEqual(step["run"], '.github/scripts/sign_release.sh "$RUNNER_TEMP/signing-venv" "$RUNNER_TEMP/dist" "$TAG"')
        for forbidden in ("pip", "python", "-m"):
            self.assertNotIn(forbidden, step["run"])
        self.assertNotIn("GLYNDOR_RELEASE_ED25519_KEY", str(jobs()["sign"].get("env", {})))

    def test_the_packages_are_installed_in_a_step_before_the_key_and_away_from_the_files(self):
        steps = jobs()["sign"]["steps"]
        names = [s.get("name", s.get("uses", "")) for s in steps]
        prepare = next(i for i, s in enumerate(steps) if "prepare_signing_venv" in s.get("run", ""))
        receive = next(i for i, s in enumerate(steps) if "download-artifact" in s.get("uses", ""))
        check = next(i for i, s in enumerate(steps) if "release_files.py" in s.get("run", ""))
        sign = next(i for i, s in enumerate(steps) if KEY in str(s))
        self.assertLess(prepare, sign, names)
        self.assertLess(check, sign, names)
        self.assertLess(receive, check, names)
        self.assertNotIn("env", steps[prepare])
        self.assertIn("-I", steps[check]["run"])

    def test_the_files_are_downloaded_into_an_empty_directory_outside_the_checkout_by_name(self):
        for name in ("attest", "sign", "sign-rehearsal", "publish"):
            for step in jobs()[name]["steps"]:
                if "download-artifact" in step.get("uses", ""):
                    self.assertTrue(step["with"]["path"].startswith("${{ runner.temp }}/"), (name, step))
                    self.assertIn("name", step["with"])
                    self.assertNotIn("merge-multiple", step["with"])
                    self.assertNotIn("pattern", step["with"])
        self.assertNotIn("merge-multiple", WORKFLOW.read_text().replace("merge-multiple`", ""))

    def test_the_jobs_that_only_need_the_scripts_check_out_the_commit_of_the_event_and_say_so_in_shell(self):
        for name in SCRIPTS_ONLY:
            steps = jobs()[name]["steps"]
            checkouts = [s for s in steps if "actions/checkout" in s.get("uses", "")]
            self.assertEqual(len(checkouts), 1, name)
            self.assertNotIn("ref", checkouts[0]["with"], name)
            self.assertIs(checkouts[0]["with"]["persist-credentials"], False, name)
            names = [s.get("name", s.get("uses")) for s in steps]
            self.assertEqual(names.index("The checkout is the commit of the event"), names.index(checkouts[0]["uses"]) + 1, name)
        self.assertEqual(jobs()["sign-rehearsal"]["steps"][0]["with"]["ref"], "${{ github.sha }}")

    def test_no_job_reads_a_commit_from_an_output_to_run_a_script_of_it_except_the_two_that_build(self):
        for name, job in jobs().items():
            refs = [s["with"].get("ref") for s in job["steps"] if "actions/checkout" in s.get("uses", "")]
            if "${{ needs.verify.outputs.commit }}" in refs:
                self.assertIn(name, ("build-deb", "build", "image-build"), name)

    def run_checkout_guard(self, head, sha, ref, verified):
        step = next(s for s in jobs()["sign"]["steps"] if s.get("name") == "The checkout is the commit of the event")["run"]
        with tempfile.TemporaryDirectory() as tmp:
            git = Path(tmp) / "git"
            git.write_text(f'#!/bin/sh\necho {head}\n')
            git.chmod(git.stat().st_mode | stat.S_IEXEC)
            return sh(step, PATH=f"{tmp}:{os.environ['PATH']}", GITHUB_SHA=sha, GITHUB_REF=ref, VERIFIED=verified)[0]

    def test_a_tag_run_must_be_at_the_verified_commit_and_a_run_on_main_at_its_own(self):
        a, b = "a" * 40, "b" * 40
        self.assertEqual(self.run_checkout_guard(a, a, "refs/tags/v1.2.3", a), 0)
        self.assertEqual(self.run_checkout_guard(a, a, "refs/tags/v1.2.3", b), 1)
        self.assertEqual(self.run_checkout_guard(a, a, "refs/heads/main", b), 0, "a manual run on main of an older tag")
        self.assertEqual(self.run_checkout_guard(b, a, "refs/heads/main", b), 1, "a tree that is not the commit of the event")
        self.assertEqual(self.run_checkout_guard(b, a, "refs/tags/v1.2.3", b), 1)


class TheCommit(unittest.TestCase):
    def test_the_tag_is_checked_for_its_shape_before_it_is_used(self):
        first = jobs()["verify"]["steps"][0]["run"]
        self.assertIn('case "$TAG" in', first)
        self.assertIn("v[0-9]*", first)
        self.assertIn("^v(0|[1-9][0-9]*)", first)
        self.assertIn('[[ "$TAG" =~ $pattern ]]', first)

    def test_every_job_that_builds_checks_out_the_verified_commit_and_none_of_them_uses_a_cache(self):
        for name in ("build-deb", "build", "image-build"):
            checkout = next(s for s in jobs()[name]["steps"] if "actions/checkout" in s.get("uses", ""))
            self.assertEqual(checkout["with"]["ref"], "${{ needs.verify.outputs.commit }}", name)
        text = WORKFLOW.read_text()
        for forbidden in ("actions/cache", "rust-cache", "cache:", "cache-from", "cache-to", "type=gha"):
            self.assertNotIn(forbidden, text)

    def test_the_release_is_made_as_a_draft_and_the_tag_is_read_before_and_after_it_becomes_public(self):
        steps = jobs()["publish"]["steps"]
        create = next(s for s in steps if s.get("name") == "Create the release")
        run = create["run"]
        self.assertIn("--verify-tag", run)
        self.assertRegex(run, r"\n\s*--draft \\\n")
        self.assertIn("--draft=false", run)
        for forbidden in ("--target", "git tag", "git push", "gh api"):
            self.assertNotIn(forbidden, run)
        self.assertLess(run.index("tag_names_the_commit\ngh release create"), run.index("gh release create"))
        self.assertEqual(run.count("tag_names_the_commit"), 4)  # defined, before, after the draft, after the publication
        self.assertEqual(jobs()["publish"]["env"]["RELEASE_COMMIT"], "${{ needs.verify.outputs.commit }}")

    def test_the_packages_are_named_by_the_version_the_tag_gives_them(self):
        stage = next(s for s in jobs()["build-deb"]["steps"] if "Stage" in s.get("name", ""))["run"]
        self.assertIn('name="epistle_${TAG#v}_${ARCH}.deb"', stage)
        self.assertNotIn("find", stage)
        self.assertNotIn("*", stage.replace("../$name", ""))


def sh(text, **env):
    done = subprocess.run(["bash", "-e", "-c", text], capture_output=True, text=True, check=False,
                          env={**{k: v for k, v in os.environ.items() if k.startswith(("PATH", "HOME"))}, **env})
    return done.returncode, done.stdout + done.stderr


class TheAuditOfARehearsal(unittest.TestCase):
    """The audit stops a release and only warns in a rehearsal, which publishes nothing."""

    def run_audit(self, dry_run):
        step = next(s for s in jobs()["verify"]["steps"] if s.get("name") == "Audit dependencies at release time")
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("cargo", "cargo-audit"):
                path = Path(tmp) / name
                path.write_text("#!/bin/sh\nexit 1\n")
                path.chmod(path.stat().st_mode | stat.S_IEXEC)
            return sh(step["run"], PATH=f"{tmp}:{os.environ['PATH']}", DRY_RUN=dry_run, TAG="v1.2.3")

    def test_a_failing_audit_stops_a_release_and_only_warns_in_a_rehearsal(self):
        code, out = self.run_audit("false")
        self.assertEqual(code, 1, out)
        code, out = self.run_audit("true")
        self.assertEqual(code, 0, out)
        self.assertIn("::warning::cargo audit fails on v1.2.3", out)

    def test_the_rehearsal_flag_comes_from_the_input_and_nothing_else(self):
        step = next(s for s in jobs()["verify"]["steps"] if s.get("name") == "Audit dependencies at release time")
        self.assertEqual(step["env"], {"DRY_RUN": "${{ inputs.dry-run && 'true' || 'false' }}"})
        self.assertNotIn("continue-on-error", step)


class WhoMayRun(unittest.TestCase):
    """The steps run as written, with the events and refs a real run could have."""

    def test_only_a_release_tag_or_a_dispatch_from_main_or_a_tag_may_sign_attest_or_publish(self):
        allowed = [("push", "refs/tags/v1.2.3"), ("workflow_dispatch", "refs/heads/main"), ("workflow_dispatch", "refs/tags/v1.2.3")]
        refused = [("push", "refs/heads/main"), ("push", "refs/heads/feature"), ("workflow_dispatch", "refs/heads/feature"),
                   ("workflow_dispatch", "refs/heads/Main"), ("pull_request", "refs/pull/1/merge"), ("schedule", "refs/heads/main"),
                   ("workflow_dispatch", "refs/heads/main2"), ("push", "refs/tags/release")]
        for job in ("attest", "sign", "publish"):
            text = jobs()[job]["steps"][0]["run"]
            for event, ref in allowed:
                self.assertEqual(sh(text, GITHUB_EVENT_NAME=event, GITHUB_REF=ref)[0], 0, (job, event, ref))
            for event, ref in refused:
                self.assertEqual(sh(text, GITHUB_EVENT_NAME=event, GITHUB_REF=ref)[0], 1, (job, event, ref))

    def run_create(self, reads, files=True):
        """The create step against a git that answers each read of the tag in turn and a gh that records its calls."""
        text = next(s for s in jobs()["publish"]["steps"] if s.get("name") == "Create the release")["run"]
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "reads").write_text("\n".join(reads) + "\n")
            git = tmp / "git"
            git.write_text('#!/bin/sh\nread line < "' + str(tmp / "reads") + '"\nsed -i 1d "' + str(tmp / "reads") + '"\n'
                           'case "$line" in none) ;; *) printf "%s\\trefs/tags/v1.2.3\\n" "$line";; esac\n')
            gh = tmp / "gh"
            gh.write_text('#!/bin/sh\necho "$*" >> "' + str(tmp / "calls") + '"\n')
            for tool in (git, gh):
                tool.chmod(tool.stat().st_mode | stat.S_IEXEC)
            code, out = sh(text, PATH=f"{tmp}:{os.environ['PATH']}", TAG="v1.2.3", RELEASE_COMMIT=commit, GH_TOKEN="t",
                           GITHUB_SERVER_URL="https://example.org", GITHUB_REPOSITORY="o/r", RUNNER_TEMP=str(tmp))
            calls = (tmp / "calls").read_text().splitlines() if (tmp / "calls").exists() else []
            return code, [" ".join(c.split()[:2]) + (" --draft=false" if "--draft=false" in c else "") for c in calls]

    def test_a_tag_that_stays_puts_the_release_public(self):
        ok = "a" * 40
        code, calls = self.run_create([ok, ok, ok])
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["release create", "release edit --draft=false"])

    def test_a_tag_moved_before_the_draft_creates_nothing(self):
        code, calls = self.run_create(["b" * 40])
        self.assertEqual((code, calls), (1, []))

    def test_a_tag_moved_while_the_draft_was_made_deletes_the_draft_and_never_publishes(self):
        ok = "a" * 40
        code, calls = self.run_create([ok, "b" * 40])
        self.assertEqual(code, 1)
        self.assertEqual(calls, ["release create", "release delete"])

    def test_a_tag_moved_after_publication_fails_loudly(self):
        ok = "a" * 40
        code, calls = self.run_create([ok, ok, "b" * 40])
        self.assertEqual(code, 1)
        self.assertEqual(calls, ["release create", "release edit --draft=false"])

    def test_a_deleted_tag_is_a_moved_tag(self):
        self.assertEqual(self.run_create(["none"])[0], 1)

    def test_an_annotated_tag_counts_by_its_peeled_commit(self):
        # a git that prints the tag object first and the peeled commit second
        text = next(s for s in jobs()["publish"]["steps"] if s.get("name") == "Create the release")["run"]
        commit, other = "a" * 40, "b" * 40
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            git = tmp / "git"
            git.write_text(f'#!/bin/sh\nprintf "{other}\\trefs/tags/v1.2.3\\n{commit}\\trefs/tags/v1.2.3^{{}}\\n"\n')
            gh = tmp / "gh"
            gh.write_text("#!/bin/sh\nexit 0\n")
            for tool in (git, gh):
                tool.chmod(tool.stat().st_mode | stat.S_IEXEC)
            code, _ = sh(text, PATH=f"{tmp}:{os.environ['PATH']}", TAG="v1.2.3", RELEASE_COMMIT=commit, GH_TOKEN="t",
                         GITHUB_SERVER_URL="https://example.org", GITHUB_REPOSITORY="o/r", RUNNER_TEMP=str(tmp))
            self.assertEqual(code, 0)

    def test_the_signing_environment_is_never_made_where_the_key_is(self):
        script = HERE / "prepare_signing_venv.sh"
        with tempfile.TemporaryDirectory() as tmp:
            for env, fragment in (({"GLYNDOR_RELEASE_ED25519_KEY": "k"}, "signing key is in the environment"),):
                done = subprocess.run(["bash", str(script), str(Path(tmp) / "venv")], capture_output=True, text=True,
                                      env={**os.environ, **env}, check=False)
                self.assertEqual(done.returncode, 1)
                self.assertIn(fragment, done.stderr)
                self.assertFalse((Path(tmp) / "venv").exists())
            (Path(tmp) / "already").mkdir()
            done = subprocess.run(["bash", str(script), str(Path(tmp) / "already")], capture_output=True, text=True,
                                  env={k: v for k, v in os.environ.items() if k != "GLYNDOR_RELEASE_ED25519_KEY"}, check=False)
            self.assertEqual(done.returncode, 1)
            self.assertIn("already exists", done.stderr)


class NoInterpolation(unittest.TestCase):
    def test_no_run_reads_the_event_the_inputs_or_the_needs_inside_its_text(self):
        pattern = re.compile(r"\$\{\{\s*(github|inputs|needs|secrets|env)\.")
        for name, job in jobs().items():
            for step in job.get("steps", []):
                self.assertIsNone(pattern.search(step.get("run", "")), (name, step.get("name")))


if __name__ == "__main__":
    unittest.main()
