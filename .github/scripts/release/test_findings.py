"""One attack for each finding of the review of the release workflow, run against the code that stops it."""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import ci_yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import images  # noqa: E402
import release_files  # noqa: E402
import verify_signatures  # noqa: E402
from release.test_release_files import deb, make_dist, write_sums  # noqa: E402

ROOT = HERE.parents[2]
SCRIPTS = HERE.parent
IMAGE = "ghcr.io/glyndor/epistle"
TAG = "v1.2.3"
COMMIT = "a" * 40
D1, D2, D3 = ("sha256:" + c * 64 for c in "123")


def jobs():
    return ci_yaml.load(ROOT / ".github/workflows/release.yml")["jobs"]


def tool(directory, name, body):
    path = Path(directory) / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


@unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb is not installed")
class AttestedPackagesAreTheBuildersOwn(unittest.TestCase):
    """Finding 1: the job that gathers the packages runs dependency code and could swap them."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dist = Path(self.tmp.name) / "dist"
        make_dist(self.dist)

    def sums(self):
        write_sums(self.dist)

    def digests(self):
        return {kind: hashlib.sha256((self.dist / name).read_bytes()).hexdigest() for kind, name in release_files.packages(TAG).items()}

    def test_a_package_swapped_by_the_gathering_job_is_not_the_one_that_was_attested(self):
        own = self.digests()
        self.assertEqual(release_files.same_packages(self.dist, TAG, own), [])
        # the wrapper puts a different package, with the same control fields, under the same name
        (self.dist / "epistle_1.2.3_amd64.deb").unlink()
        deb(self.dist / "epistle_1.2.3_amd64.deb", arch="amd64", payload=b"a different program")
        self.sums()
        self.assertEqual(release_files.check(self.dist, TAG, "built"), [], "every check of the gathered directory still passes")
        problems = release_files.same_packages(self.dist, TAG, own)
        self.assertEqual(problems, ["epistle_1.2.3_amd64.deb is not the package its builder produced"])

    def test_an_rpm_swapped_by_the_gathering_job_or_one_with_no_digest_is_refused(self):
        own = self.digests()
        name = "epistle-1.2.3-1.glyndor.any.aarch64.rpm"
        (self.dist / name).write_bytes(b"a different rpm")
        self.sums()
        self.assertEqual(release_files.check(self.dist, TAG, "built"), [])
        self.assertEqual(release_files.same_packages(self.dist, TAG, own), [f"{name} is not the package its builder produced"])
        del own["rpm-aarch64"]
        self.assertIn("rpm-aarch64: the digest handed over is not a SHA-256: ''", release_files.same_packages(self.dist, TAG, own))

    def test_a_stable_tag_has_both_rpm_packages_and_a_prerelease_has_none(self):
        self.assertEqual(sorted(release_files.packages(TAG)), ["amd64", "arm64", "rpm-aarch64", "rpm-x86_64"])
        self.assertEqual(sorted(release_files.packages("v1.2.3-rc.1")), ["amd64", "arm64"])
        self.assertFalse([n for n in release_files.names("v1.2.3-rc.1", "signed") if n.endswith((".rpm", ".rpm.sig"))])
        for name in ("epistle-1.2.3-1.glyndor.any.x86_64.rpm", "epistle-1.2.3-1.glyndor.any.x86_64.rpm.sig"):
            self.assertIn(name, release_files.names(TAG, "signed"))

    def test_a_release_without_one_of_its_rpm_packages_or_with_another_is_refused(self):
        name = "epistle-1.2.3-1.glyndor.any.x86_64.rpm"
        (self.dist / name).rename(self.dist / "epistle-9.9.9-1.glyndor.any.x86_64.rpm")
        problems = release_files.check(self.dist, TAG, "built")
        self.assertIn(f"missing: {name}", problems)
        self.assertIn("unexpected entry: epistle-9.9.9-1.glyndor.any.x86_64.rpm", problems)

    def test_the_digest_handed_over_has_to_be_a_sha256(self):
        for bad in ("", "abc", "G" * 64, "0" * 63):
            problems = release_files.same_packages(self.dist, TAG, {"amd64": bad, "arm64": "0" * 64})
            self.assertTrue(any("not a SHA-256" in p for p in problems), bad)

    def test_a_package_directory_of_a_builder_holds_exactly_its_package(self):
        own = Path(self.tmp.name) / "own"
        own.mkdir()
        deb(own / "epistle_1.2.3_amd64.deb", arch="amd64")
        self.assertEqual(release_files.check_package(own, TAG, "amd64"), [])
        self.assertTrue(release_files.check_package(own, TAG, "rpm-x86_64"))
        self.assertEqual(release_files.check_package(own, "v1.2.3-rc.1", "rpm-x86_64"),
                         ["a release of v1.2.3-rc.1 has no package of the kind 'rpm-x86_64'"])
        deb(own / "epistle_9.9.9_amd64.deb", version="9.9.9", arch="amd64")
        self.assertEqual(release_files.check_package(own, TAG, "amd64"), ["unexpected entry: epistle_9.9.9_amd64.deb"])
        (own / "epistle_9.9.9_amd64.deb").unlink()
        self.assertTrue(release_files.check_package(own, TAG, "arm64"))

    def test_the_workflow_attests_the_builders_packages_and_the_later_jobs_compare_their_copies(self):
        steps = jobs()["attest"]["steps"]
        names = [s.get("name", "") for s in steps]
        downloads = [s["with"]["name"] for s in steps if "download-artifact" in s.get("uses", "")]
        self.assertEqual(sorted(downloads), ["epistle-deb-amd64", "epistle-deb-arm64", "epistle-rpm-aarch64", "epistle-rpm-x86_64", "release-dist"])
        subject = next(s for s in steps if "attest-build-provenance" in s.get("uses", ""))["with"]["subject-path"]
        self.assertIn("/own/amd64/", subject)
        self.assertIn("/own/arm64/", subject)
        self.assertNotIn("/dist/epistle_", subject)
        self.assertIn("/own/rpm-x86_64/", subject)
        self.assertIn("/own/rpm-aarch64/", subject)
        self.assertEqual(jobs()["attest"]["outputs"], {
            "deb-amd64": "${{ steps.digests.outputs.amd64 }}", "deb-arm64": "${{ steps.digests.outputs.arm64 }}",
            "rpm-x86_64": "${{ steps.digests.outputs.rpm-x86_64 }}", "rpm-aarch64": "${{ steps.digests.outputs.rpm-aarch64 }}",
        })
        self.assertIn("sign", jobs())
        self.assertIn("attest", jobs()["sign"]["needs"])
        self.assertIn("same-packages", next(s for s in jobs()["sign"]["steps"] if s.get("name") == "The packages are the ones that were attested")["run"])
        self.assertIn("attest", jobs()["publish"]["needs"])
        publish = next(s for s in jobs()["publish"]["steps"] if s.get("name") == "The packages are the ones that were attested")
        self.assertIn('sha256sum "$RUNNER_TEMP/dist/epistle_${version}_${arch}.deb"', publish["run"])
        self.assertLess(names.index("Check the packages of the builders and take their digests"), names.index("Attest build provenance"))


class PublishComparesThePackages(unittest.TestCase):
    """Finding 1, at the last job before the release exists: the step as written, with real files."""

    def run_step(self, amd64_bytes, arm64_bytes, want_amd64, want_arm64, tag=TAG, rpm=b"rpm", want_rpm=None):
        step = next(s for s in jobs()["publish"]["steps"] if s.get("name") == "The packages are the ones that were attested")["run"]
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            dist.mkdir()
            (dist / "epistle_1.2.3_amd64.deb").write_bytes(amd64_bytes)
            (dist / "epistle_1.2.3_arm64.deb").write_bytes(arm64_bytes)
            if "-" not in tag:
                for arch in ("x86_64", "aarch64"):
                    (dist / f"epistle-1.2.3-1.glyndor.any.{arch}.rpm").write_bytes(rpm)
            else:
                version = tag[1:]
                (dist / f"epistle_{version}_amd64.deb").write_bytes(amd64_bytes)
                (dist / f"epistle_{version}_arm64.deb").write_bytes(arm64_bytes)
            want_rpm = hashlib.sha256(b"rpm").hexdigest() if want_rpm is None else want_rpm
            done = subprocess.run(["bash", "-e", "-c", step], capture_output=True, text=True, check=False,
                                  env={**os.environ, "RUNNER_TEMP": tmp, "TAG": tag, "DEB_AMD64": want_amd64, "DEB_ARM64": want_arm64,
                                       "RPM_X86_64": want_rpm, "RPM_AARCH64": want_rpm})
            return done.returncode, done.stdout + done.stderr

    def test_the_attested_packages_pass_and_a_swapped_one_does_not(self):
        sha = lambda data: hashlib.sha256(data).hexdigest()  # noqa: E731
        self.assertEqual(self.run_step(b"a", b"b", sha(b"a"), sha(b"b"))[0], 0)
        code, out = self.run_step(b"swapped", b"b", sha(b"a"), sha(b"b"))
        self.assertEqual(code, 1)
        self.assertIn("amd64 package is not the one that was attested", out)
        self.assertEqual(self.run_step(b"a", b"swapped", sha(b"a"), sha(b"b"))[0], 1)
        self.assertEqual(self.run_step(b"a", b"b", "", sha(b"b"))[0], 1, "a digest that never arrived is not a match")

    def test_a_swapped_rpm_or_one_with_no_digest_stops_the_publication_and_a_prerelease_has_none_to_check(self):
        sha = lambda data: hashlib.sha256(data).hexdigest()  # noqa: E731
        code, out = self.run_step(b"a", b"b", sha(b"a"), sha(b"b"), rpm=b"swapped")
        self.assertEqual(code, 1)
        self.assertIn("x86_64 rpm is not the one that was attested", out)
        self.assertEqual(self.run_step(b"a", b"b", sha(b"a"), sha(b"b"), want_rpm="")[0], 1)
        self.assertEqual(self.run_step(b"a", b"b", sha(b"a"), sha(b"b"), tag="v1.2.3-rc.1", want_rpm="")[0], 0)


@unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb is not installed")
class TheKeyIsNotInheritedByTheParser(unittest.TestCase):
    """Finding 7: the parser of the bytes of a package must not hold the signing key."""

    def test_dpkg_deb_never_sees_the_key_whoever_set_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "env"
            tool(tmp, "dpkg-deb", f'env > "{log}"\necho epistle\n')
            package = Path(tmp) / "x.deb"
            package.write_bytes(b"")
            old = dict(os.environ)
            os.environ["PATH"] = f"{tmp}:{old['PATH']}"
            os.environ["GLYNDOR_RELEASE_ED25519_KEY"] = "secret-seed"
            try:
                release_files.control_field(package, "Package")
            finally:
                os.environ.clear()
                os.environ.update(old)
            self.assertNotIn("GLYNDOR_RELEASE_ED25519_KEY", log.read_text())
            self.assertNotIn("secret-seed", log.read_text())

    def test_the_signing_script_checks_the_files_without_the_key_in_the_process(self):
        script = (SCRIPTS / "sign_release.sh").read_text()
        for line in script.splitlines():
            if "release_files.py" in line and not line.lstrip().startswith("#"):
                self.assertIn("env -u GLYNDOR_RELEASE_ED25519_KEY", line)


class SignaturesUnderThePinnedKey(unittest.TestCase):
    """Finding 8: a signature that does not verify under the key people were given authenticates nothing."""

    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dist = Path(self.tmp.name) / "dist"
        self.real, self.other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        import base64

        raw = self.real.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.pinned = Path(self.tmp.name) / "key.b64"
        self.pinned.write_text(base64.b64encode(raw).decode().rstrip("=") + "\n")
        make_dist(self.dist)

    def sign_all(self, key):
        for name in release_files.built_names(TAG):
            (self.dist / f"{name}.sig").write_bytes(key.sign((self.dist / name).read_bytes()))

    def test_signatures_made_with_the_pinned_key_pass(self):
        self.sign_all(self.real)
        self.assertEqual(verify_signatures.verify(self.dist, TAG, self.pinned), [])

    def test_well_formed_signatures_of_another_seed_are_refused_for_every_file(self):
        self.sign_all(self.other)
        problems = verify_signatures.verify(self.dist, TAG, self.pinned)
        self.assertEqual(len(problems), len(release_files.built_names(TAG)))
        self.assertTrue(all("does not verify under the pinned release key" in p for p in problems))
        self.assertEqual(release_files.check(self.dist, TAG, "signed"), [], "everything the old checks looked at is fine")

    def test_one_altered_file_or_one_empty_signature_is_refused(self):
        self.sign_all(self.real)
        original = (self.dist / f"epistle-{TAG}.cdx.json").read_text()
        (self.dist / f"epistle-{TAG}.cdx.json").write_text('{"changed": true}')
        write_sums(self.dist)
        problems = verify_signatures.verify(self.dist, TAG, self.pinned)
        self.assertTrue(any("cdx.json.sig does not verify" in p for p in problems), problems)
        (self.dist / f"epistle-{TAG}.cdx.json").write_text(original)
        write_sums(self.dist)
        (self.dist / f"epistle-{TAG}.cdx.json.sig").write_bytes(b"")
        self.assertTrue(verify_signatures.verify(self.dist, TAG, self.pinned))

    def test_a_key_file_that_is_not_one_key_is_an_error(self):
        self.sign_all(self.real)
        for text in ("", "not base64!!\n", "AAAA\n", "a\nb\n"):
            self.pinned.write_text(text)
            with self.assertRaises(ValueError):
                verify_signatures.verify(self.dist, TAG, self.pinned)

    def test_the_repository_pins_a_key_of_the_right_shape_and_the_workflow_verifies_before_publishing(self):
        key = ROOT / ".github/release/ed25519-public-key.b64"
        verify_signatures.load_key(key)
        self.assertEqual(len([l for l in key.read_text().splitlines() if l.strip()]), 1)
        self.assertIn("verify-signatures", jobs()["publish"]["needs"])
        step = next(s for s in jobs()["verify-signatures"]["steps"] if s.get("name") == "Every signature verifies under the pinned key")
        self.assertIn("verify_signatures.py", step["run"])
        self.assertIn("-I", step["run"])
        self.assertIn("ed25519-public-key.b64", step["run"])
        self.assertNotIn("secrets.", str(jobs()["verify-signatures"]))


class ARegistryThatCanBeWrittenTo(unittest.TestCase):
    """Findings 3 to 6, against a registry client that serves what the test says the registry holds."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "registry.json"
        tool(self.tmp.name, "skopeo", f'''python3 - "$@" <<'PY'
import json, sys
state = json.load(open("{self.state}"))
args = sys.argv[1:]
if state.get("down"):
    sys.stderr.write("connection refused"); sys.exit(2)
ref = args[-1].removeprefix("docker://")
if args[0] == "list-tags":
    print(json.dumps({{"Tags": state["tags"]}})); sys.exit(0)
entry = state["images"].get(ref)
if entry is None:
    sys.stderr.write("manifest unknown"); sys.exit(1)
print(json.dumps(entry["raw"]) if "--raw" in args else json.dumps({{"Digest": entry["digest"], "Labels": entry.get("labels", {{}})}}))
PY
''')
        self.old = os.environ["PATH"]
        os.environ["PATH"] = f"{self.tmp.name}:{self.old}"
        self.addCleanup(lambda: os.environ.__setitem__("PATH", self.old))

    def registry(self, images=None, tags=(), down=False):
        self.state.write_text(json.dumps({"images": images or {}, "tags": list(tags), "down": down}))

    def published(self, tag, digest, revision):
        return {f"{IMAGE}:{tag}": {"digest": digest, "raw": {}, "labels": {images.REVISION: revision}}}

    # Finding 3: images-only must not publish a version again with another commit
    def test_a_tag_that_exists_is_never_replaced_by_a_normal_release(self):
        self.registry(self.published("1.2.3-amd64", D1, COMMIT))
        with self.assertRaises(images.Refusal) as caught:
            images.decide(IMAGE, "1.2.3-amd64", COMMIT, False)
        self.assertIn("never replaced", str(caught.exception))

    def test_images_only_reuses_an_image_built_from_the_verified_commit_and_refuses_another(self):
        self.registry(self.published("1.2.3-amd64", D1, COMMIT))
        self.assertEqual(images.decide(IMAGE, "1.2.3-amd64", COMMIT, True), ("reuse", D1))
        self.registry(self.published("1.2.3-amd64", D1, "b" * 40))
        with self.assertRaises(images.Refusal):
            images.decide(IMAGE, "1.2.3-amd64", COMMIT, True)

    def test_a_missing_tag_is_built_and_a_registry_that_cannot_answer_builds_nothing(self):
        self.registry()
        self.assertEqual(images.decide(IMAGE, "1.2.3-arm64", COMMIT, False), ("build", ""))
        self.registry(down=True)
        with self.assertRaises(images.Refusal):
            images.decide(IMAGE, "1.2.3-arm64", COMMIT, True)

    def test_hostile_names_and_commits_are_refused_before_the_registry_is_asked(self):
        self.registry()
        for tag in ("1.2.3 -x", "../x", "a;b", ""):
            with self.assertRaises(images.Refusal):
                images.decide(IMAGE, tag, COMMIT, False)
        with self.assertRaises(images.Refusal):
            images.decide(IMAGE, "1.2.3-amd64", "main", False)
        with self.assertRaises(images.Refusal):
            images.decide("--help", "1.2.3-amd64", COMMIT, False)

    # Finding 4: the list holds the digests the builders produced, nothing resolved again by tag
    def test_a_manifest_list_that_holds_another_image_is_refused(self):
        def manifest(*pairs):
            return json.dumps({"manifests": [{"digest": d, "platform": {"architecture": a}} for a, d in pairs]})
        self.assertTrue(images.check_list(manifest(("amd64", D1), ("arm64", D2)), D1, D2))
        for held in (manifest(("amd64", D1), ("arm64", D3)), manifest(("amd64", D1)), manifest(("amd64", D1), ("arm64", D2), ("s390x", D3)),
                     manifest(("amd64", D2), ("arm64", D1))):
            with self.assertRaises(images.Refusal):
                images.check_list(held, D1, D2)
        for bad in ("latest", "sha256:abc", ""):
            with self.assertRaises(images.Refusal):
                images.check_list(manifest(), bad, D2)

    def test_the_workflow_assembles_by_digest_and_never_reads_a_builders_tag_again(self):
        run = next(s for s in jobs()["image-manifest"]["steps"] if s.get("name") == "Assemble the manifest list from the two digests")["run"]
        self.assertIn('podman manifest add "release-list" "docker://${REGISTRY_IMAGE}@${amd64}"', run)
        self.assertIn('podman manifest add "release-list" "docker://${REGISTRY_IMAGE}@${arm64}"', run)
        self.assertNotIn("-amd64\"", run)
        self.assertNotIn("-arm64\"", run)
        self.assertIn("images.py list", run)

    # Finding 5: nothing consumable before the attestation has been checked
    def test_the_manifest_goes_to_a_tag_nobody_consumes_and_the_attestation_is_checked_before_any_tag_moves(self):
        steps = jobs()["image-manifest"]["steps"]
        names = [s.get("name", s.get("uses", "")) for s in steps]
        assemble = next(s for s in steps if s.get("name") == "Assemble the manifest list from the two digests")["run"]
        self.assertIn(":pending-${crate_version}", assemble)
        self.assertNotIn(':${crate_version}"', assemble)
        verify_index = names.index("The attestation verifies before any tag moves")
        self.assertLess(names.index("Assemble the manifest list from the two digests"), verify_index)
        attest_index = next(i for i, step in enumerate(steps) if "attest-build-provenance" in step.get("uses", ""))
        self.assertLess(attest_index, verify_index)
        self.assertIn("gh attestation verify", steps[verify_index]["run"])
        self.assertIn("image-manifest", jobs()["image-promote"]["needs"])
        for step in jobs()["image-build"]["steps"] + jobs()["image-manifest"]["steps"]:
            self.assertNotRegex(step.get("run", ""), r"podman push[^\n]*:\$\{?(crate_)?version\}?\"?\s*$")

    # Finding 6: an old version never takes the floating tags back
    def test_floating_tags_move_only_to_the_highest_stable_version_of_their_line(self):
        self.assertEqual(images.promote_tags("1.2.4", ["1.2.3", "1.2.4", "1.1.9", "1.9.0", "2.0.0", "1.2", "1", "latest"]), ["1.2.4", "1.2"])
        self.assertEqual(images.promote_tags("1.2.3", ["1.2.3", "1.2.4"]), ["1.2.3"])
        self.assertEqual(images.promote_tags("1.9.0", ["1.2.4", "1.9.0"]), ["1.9.0", "1.9", "1"])
        self.assertEqual(images.promote_tags("1.2.3", []), ["1.2.3", "1.2", "1"])
        self.assertEqual(images.promote_tags("0.13.4", ["0.13.3", "0.14.0"]), ["0.13.4", "0.13"])
        self.assertEqual(images.promote_tags("1.2.3-rc.1", ["1.2.2"]), ["1.2.3-rc.1"])
        self.assertEqual(images.promote_tags("1.10.0", ["1.9.0", "1.2.0"]), ["1.10.0", "1.10", "1"])

    def test_the_exact_tag_is_never_given_another_image(self):
        self.registry({f"{IMAGE}:1.2.3": {"digest": D1, "raw": {}}}, tags=["1.2.3"])
        self.assertEqual(images.promote(IMAGE, "1.2.3", D1), ["1.2.3", "1.2", "1"])
        with self.assertRaises(images.Refusal):
            images.promote(IMAGE, "1.2.3", D2)

    def test_the_promotion_is_one_job_at_a_time_and_reads_what_the_registry_holds(self):
        promote = jobs()["image-promote"]
        self.assertEqual(promote["concurrency"], {"group": "release-image-tags", "cancel-in-progress": False})
        run = next(s for s in promote["steps"] if s.get("name") == "Move the tags this version is allowed to move")["run"]
        self.assertIn("images.py promote", run)
        self.assertIn("image_tags.py", run)
        self.assertIn('skopeo copy --all "docker://${REGISTRY_IMAGE}@${DIGEST}"', run)
        for step in jobs()["image-manifest"]["steps"]:
            self.assertNotIn("skopeo copy", step.get("run", ""))


if __name__ == "__main__":
    unittest.main()
