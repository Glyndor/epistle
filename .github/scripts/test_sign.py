#!/usr/bin/env python3
"""Tests for `.github/scripts/sign.py`.

Run from the repository root with:

	python3 -m unittest discover -s .github/scripts -p 'test_*.py' -v

Exercises the script as an external command: every case below drives `sign.py`
through `subprocess`, the way the release workflow drives it. Anything that
fails *inside* sign.py has to surface as an exit code and a stderr line; that
is the contract this suite pins down.
"""

import base64
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
	Encoding,
	NoEncryption,
	PrivateFormat,
)


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SIGN_PY = REPO_ROOT / ".github" / "scripts" / "sign.py"


def _fresh_key() -> tuple[str, bytes]:
	"""Generate a brand-new Ed25519 key for this test.

	Returns (base64-encoded seed, raw 32-byte seed). The raw seed is what
	the script will reconstruct; passing the base64 string into the script
	is the only thing the test does that resembles production behaviour.
	"""
	private_key = Ed25519PrivateKey.generate()
	raw = private_key.private_bytes(
		encoding=Encoding.Raw,
		format=PrivateFormat.Raw,
		encryption_algorithm=NoEncryption(),
	)
	return base64.b64encode(raw).decode("ascii"), raw


def _run_sign(extra_env: dict[str, str] | None, *args: str) -> subprocess.CompletedProcess:
	"""Invoke `sign.py` as a subprocess with a controlled environment.

	`extra_env=None` removes `GLYNDOR_RELEASE_ED25519_KEY` from the
	inherited environment, so a CI runner that happens to have it set
	cannot make the negative tests pass by accident.
	"""
	env = os.environ.copy()
	if extra_env is None:
		env.pop("GLYNDOR_RELEASE_ED25519_KEY", None)
	else:
		env.update(extra_env)
	return subprocess.run(
		[sys.executable, str(SIGN_PY), *args],
		capture_output=True,
		env=env,
		cwd=str(REPO_ROOT),
		text=True,
		check=False,
	)


class TestSignPy(unittest.TestCase):
	"""Each test names the specific failure mode it expects.

	The point of that is not style. `sign.py` used to swallow
	out-of-alphabet characters and sign with whatever 32 bytes the
	lax decoder produced; the third test here fails if the script ever
	loses that defence again. The fourth fails if a wrong-length key
	stops naming its actual length in the error. The assertions are
	tied to the message, not just the exit code.
	"""

	def test_valid_key_signs_and_signature_verifies(self) -> None:
		key_b64, raw = _fresh_key()
		with tempfile.TemporaryDirectory() as tmpdir:
			tmp = Path(tmpdir)
			payload = tmp / "payload.bin"
			sig = tmp / "payload.sig"
			payload.write_bytes(b"hello, release")
			proc = _run_sign(
				{"GLYNDOR_RELEASE_ED25519_KEY": key_b64},
				str(payload),
				str(sig),
			)
			self.assertEqual(proc.returncode, 0, msg=proc.stderr)
			self.assertTrue(sig.exists(), "signature file was not written")
			# The signature has to verify with the public key derived from
			# the seed we just generated — not with any other key.
			Ed25519PrivateKey.from_private_bytes(raw).public_key().verify(
				sig.read_bytes(),
				b"hello, release",
			)

	def test_trailing_newline_produces_same_signature(self) -> None:
		# The case that hits in practice: CI secret stores store text
		# values, so the same key shows up with a trailing newline once in
		# a while. The signature must be byte-identical.
		key_b64, _ = _fresh_key()
		with tempfile.TemporaryDirectory() as tmpdir:
			tmp = Path(tmpdir)
			payload = tmp / "payload.bin"
			sig_clean = tmp / "clean.sig"
			sig_dirty = tmp / "dirty.sig"
			payload.write_bytes(b"payload")
			clean = _run_sign(
				{"GLYNDOR_RELEASE_ED25519_KEY": key_b64},
				str(payload),
				str(sig_clean),
			)
			dirty = _run_sign(
				{"GLYNDOR_RELEASE_ED25519_KEY": key_b64 + "\n"},
				str(payload),
				str(sig_dirty),
			)
			self.assertEqual(clean.returncode, 0, msg=clean.stderr)
			self.assertEqual(dirty.returncode, 0, msg=dirty.stderr)
			self.assertEqual(
				sig_clean.read_bytes(),
				sig_dirty.read_bytes(),
				"a trailing newline changed the signature, which means "
				"the same key produced two different ones",
			)

	def test_non_base64_character_does_not_produce_a_valid_signature(self) -> None:
		# '!' is outside the base64 alphabet. Without `validate=True`, the
		# legacy decoder silently skipped the byte and returned 32 different
		# bytes — and the script signed with them. The signature then failed
		# verification against the public key the operator intended, but
		# nothing in the script noticed, and the wrong-key signature is what
		# reached the user.
		#
		# With the fix, the decoder raises before any signing happens and
		# the script refuses outright. The assertion is on the specific
		# message the decoder produces with `validate=True` — that message
		# is the proof that the validate branch is active. Lenient mode
		# raises too, but with a different downstream-shaped message, and
		# catching that difference is the whole point of this test.
		key_b64, raw = _fresh_key()
		intended_pub = Ed25519PrivateKey.from_private_bytes(raw).public_key()
		corrupted = key_b64[:5] + "!" + key_b64[6:]
		with tempfile.TemporaryDirectory() as tmpdir:
			tmp = Path(tmpdir)
			payload = tmp / "payload.bin"
			sig = tmp / "payload.sig"
			payload.write_bytes(b"hello")
			proc = _run_sign(
				{"GLYNDOR_RELEASE_ED25519_KEY": corrupted},
				str(payload),
				str(sig),
			)
			self.assertNotEqual(
				proc.returncode, 0,
				"corrupted key must not produce a signature; the script "
				"succeeded and may have signed with garbage bytes",
			)
			self.assertFalse(
				sig.exists(),
				"a signature file was written despite the key being invalid; "
				"this is the defect the validate=True fix prevents",
			)
			# The exact rejection matters: `validate=True` makes the
			# decoder raise 'Only base64 data is allowed'; lenient mode
			# raises 'Incorrect padding' instead. Only the first message
			# proves the validate branch is in the call.
			self.assertIn(
				"Only base64 data is allowed", proc.stderr,
				"the rejection must come from the validate=True branch, "
				f"not from a downstream padding check; stderr was {proc.stderr!r}",
			)
			self.assertNotIn(
				"Incorrect padding", proc.stderr,
				"a padding error means the lenient decoder raised first; "
				"the validate=True defence is not active",
			)

	def test_short_key_fails_naming_the_length(self) -> None:
		# 16 bytes raw -> 24 base64 characters, no padding required. Must
		# be rejected with a message that names BOTH the wrong length and
		# the correct one, so an operator staring at a broken release at
		# 3 a.m. sees the diagnosis immediately.
		short_b64 = base64.b64encode(b"\x00" * 16).decode("ascii")
		with tempfile.TemporaryDirectory() as tmpdir:
			tmp = Path(tmpdir)
			payload = tmp / "payload.bin"
			sig = tmp / "payload.sig"
			payload.write_bytes(b"hi")
			proc = _run_sign(
				{"GLYNDOR_RELEASE_ED25519_KEY": short_b64},
				str(payload),
				str(sig),
			)
			self.assertNotEqual(proc.returncode, 0)
			self.assertFalse(sig.exists())
			self.assertIn(
				"16 bytes", proc.stderr,
				"stderr must name the actual length (16 bytes), not just "
				"complain that something is wrong",
			)
			self.assertIn(
				"32 bytes", proc.stderr,
				"stderr must name the required length (32 bytes) so the "
				"operator does not have to look it up",
			)

	def test_missing_env_var_fails_and_writes_no_file(self) -> None:
		# Pass `extra_env=None` so the test is robust against a CI runner
		# that happens to have GLYNDOR_RELEASE_ED25519_KEY in its
		# environment — the variable has to be missing for the script,
		# not for whoever happens to run the test.
		with tempfile.TemporaryDirectory() as tmpdir:
			tmp = Path(tmpdir)
			payload = tmp / "payload.bin"
			sig = tmp / "payload.sig"
			payload.write_bytes(b"hi")
			proc = _run_sign(None, str(payload), str(sig))
			self.assertEqual(
				proc.returncode, 1,
				"missing env var must exit 1, the documented contract",
			)
			self.assertFalse(
				sig.exists(),
				"no .sig may be written when the key is absent",
			)
			self.assertIn("GLYNDOR_RELEASE_ED25519_KEY", proc.stderr)
			self.assertIn("not set", proc.stderr.lower())

	def test_signature_written_to_explicit_or_default_path(self) -> None:
		# Two halves in one test, both about where the .sig lands.
		key_b64, _ = _fresh_key()
		with tempfile.TemporaryDirectory() as tmpdir:
			tmp = Path(tmpdir)
			# Explicit path: the script writes wherever argv[2] says.
			explicit_payload = tmp / "alpha.bin"
			explicit_sig = tmp / "custom_name.sig"
			explicit_payload.write_bytes(b"a")
			explicit = _run_sign(
				{"GLYNDOR_RELEASE_ED25519_KEY": key_b64},
				str(explicit_payload),
				str(explicit_sig),
			)
			self.assertEqual(explicit.returncode, 0, msg=explicit.stderr)
			self.assertTrue(
				explicit_sig.exists(),
				"explicit output path was not used",
			)
			# Default path: omitting argv[2] must produce <input>.sig.
			default_payload = tmp / "beta.bin"
			default_payload.write_bytes(b"b")
			default = _run_sign(
				{"GLYNDOR_RELEASE_ED25519_KEY": key_b64},
				str(default_payload),
			)
			self.assertEqual(default.returncode, 0, msg=default.stderr)
			self.assertTrue(
				(tmp / "beta.bin.sig").exists(),
				"default <input>.sig was not produced when argv[2] was omitted",
			)


if __name__ == "__main__":
	unittest.main()
