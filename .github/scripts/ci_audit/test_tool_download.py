"""The security tools are downloaded on every run and checked against a pinned SHA-256, never compiled or cached."""

import hashlib
import io
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

import ci_yaml

ROOT = Path(__file__).resolve().parents[3]
REUSABLE = ROOT / ".github/workflows/reusable-rust-audit.yml"
TOOLS = {  # job, tool, release directory inside the archive, URL fragment
    "audit": ("cargo-audit", "cargo-audit-x86_64-unknown-linux-musl-v{v}", "rustsec/rustsec/releases/download/cargo-audit%2Fv{v}/"),
    "deny": ("cargo-deny", "cargo-deny-{v}-x86_64-unknown-linux-musl", "EmbarkStudios/cargo-deny/releases/download/{v}/"),
}


def workflow():
    return ci_yaml.load(REUSABLE)


def install_step(job, tool):
    return next(s for s in workflow()["jobs"][job]["steps"] if s.get("name") == f"Install {tool}")


class Download(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        fake = self.root / "bin"
        fake.mkdir()
        curl = fake / "curl"
        curl.write_text('#!/bin/sh\nwhile [ $# -gt 0 ]; do case "$1" in --output) out="$2"; shift;; https://*) echo "$1" > "$CURL_LOG";; esac; shift; done\ncp "$SERVED" "$out"\n')
        curl.chmod(curl.stat().st_mode | stat.S_IEXEC)
        self.fake = fake

    def serve(self, directory, data=b"binary"):
        path = self.root / "served.tgz"
        with tarfile.open(path, "w:gz") as tar:
            info = tarfile.TarInfo(f"{directory}/TOOL")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        return path

    def run_step(self, job, tool, directory, sha=None, version="1.2.3", member_data=b"binary"):
        name, folder, _ = TOOLS[job]
        served = self.root / "served.tgz"
        with tarfile.open(served, "w:gz") as tar:
            info = tarfile.TarInfo(f"{folder.format(v=version)}/{name}")
            info.size = len(member_data)
            tar.addfile(info, io.BytesIO(member_data))
        digest = sha or hashlib.sha256(served.read_bytes()).hexdigest()
        temp = self.root / "temp"
        temp.mkdir(exist_ok=True)
        path_file = self.root / "path"
        path_file.write_text("")
        done = subprocess.run(["bash", "-e", "-c", install_step(job, tool)["run"]], capture_output=True, text=True, check=False,
                              env={**os.environ, "PATH": f"{self.fake}:{os.environ['PATH']}", "SERVED": str(served),
                                   "CURL_LOG": str(self.root / "url"), "RUNNER_TEMP": str(temp), "GITHUB_PATH": str(path_file),
                                   "TOOL_VERSION": version, "TOOL_SHA256": digest})
        return done, temp, path_file

    def test_each_tool_is_installed_from_its_release_url_when_the_digest_matches(self):
        for job, (name, _, fragment) in TOOLS.items():
            with self.subTest(tool=name):
                done, temp, path_file = self.run_step(job, name, None)
                self.assertEqual(done.returncode, 0, done.stderr)
                installed = temp / "tools" / name / name
                self.assertEqual(installed.read_bytes(), b"binary")
                self.assertTrue(os.access(installed, os.X_OK))
                self.assertEqual(path_file.read_text().strip(), str(installed.parent))
                url = (self.root / "url").read_text().strip()
                self.assertTrue(url.startswith("https://github.com/" + fragment.format(v="1.2.3")), url)

    def test_an_archive_that_does_not_match_installs_nothing_and_adds_nothing_to_the_path(self):
        for job, (name, _, _) in TOOLS.items():
            with self.subTest(tool=name):
                done, temp, path_file = self.run_step(job, name, None, sha="0" * 64)
                self.assertEqual(done.returncode, 1)
                self.assertIn("does not match the pinned SHA-256", done.stdout + done.stderr)
                self.assertFalse((temp / "tools").exists())
                self.assertEqual(path_file.read_text(), "")

    def test_a_version_or_a_digest_that_is_not_plain_is_refused_before_any_download(self):
        for version in ("1.2", "1.2.3;x", "../1.2.3", "v1.2.3"):
            with self.subTest(version=version):
                done, _, _ = self.run_step("audit", "cargo-audit", None, version=version)
                self.assertEqual(done.returncode, 1)
                self.assertFalse((self.root / "url").exists())
        for sha in ("abc", "A" * 64, "0" * 65):
            with self.subTest(sha=sha):
                done, _, _ = self.run_step("audit", "cargo-audit", None, sha=sha)
                self.assertEqual(done.returncode, 1)


class NothingCompiledOrCached(unittest.TestCase):
    def test_the_tools_are_never_compiled_on_the_runner_or_restored_from_a_cache(self):
        text = REUSABLE.read_text()
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("cargo install", code)
        self.assertNotIn("actions/cache", code)
        self.assertNotIn("rust-cache", code)
        self.assertNotIn("command -v cargo-", code)

    def test_the_pinned_digests_are_sha256_values_next_to_exact_versions(self):
        inputs = workflow()[True]["workflow_call"]["inputs"]
        for tool in ("audit", "deny"):
            self.assertRegex(inputs[f"cargo-{tool}-version"]["default"], r"^\d+\.\d+\.\d+$")
            self.assertRegex(inputs[f"cargo-{tool}-sha256"]["default"], r"^[0-9a-f]{64}$")

    def test_the_download_is_https_only_and_the_environment_carries_both_values(self):
        for job, (name, _, _) in TOOLS.items():
            step = install_step(job, name)["run"]
            self.assertIn("--proto '=https'", step)
            self.assertIn("sha256sum --check --strict", step)
            env = workflow()["jobs"][job]["env"]
            self.assertEqual(env["TOOL_SHA256"], "${{ inputs.cargo-%s-sha256 }}" % job)
            self.assertEqual(env["TOOL_VERSION"], "${{ inputs.cargo-%s-version }}" % job)
        # a checkout of another ref never precedes a tool that judges it
        steps = workflow()["jobs"]["audit"]["steps"]
        self.assertEqual([s for s in steps if "ref" in s.get("with", {})], [])


if __name__ == "__main__":
    unittest.main()
