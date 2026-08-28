#!/usr/bin/env python3
"""Sign a file with an Ed25519 private key (raw 32-byte seed, base64-encoded).

Usage:
  sign.py <input-file> [<output-sig-file>]

The private key is read from the GLYNDOR_RELEASE_ED25519_KEY environment variable (raw
32-byte Ed25519 seed in standard base64), never from the command line, so the
secret is not exposed in the process argument list (/proc/<pid>/cmdline).

If output-sig-file is omitted, writes to <input-file>.sig.
"""
import base64
import binascii
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> None:
	if len(sys.argv) < 2:
		print(__doc__, file=sys.stderr)
		sys.exit(1)

	key_b64 = os.environ.get("GLYNDOR_RELEASE_ED25519_KEY")
	if not key_b64:
		print("GLYNDOR_RELEASE_ED25519_KEY is not set in the environment", file=sys.stderr)
		sys.exit(1)

	input_file = sys.argv[1]
	sig_file = sys.argv[2] if len(sys.argv) > 2 else input_file + ".sig"

	# Newline characters and trailing whitespace are routine in CI secret stores.
	# Without the strip, a stray '\n' is decoded as if it were a base64 character
	# in lenient mode and silently produces 32 different bytes — and a signature
	# with the wrong key.
	stripped = key_b64.strip()
	# Standard base64 requires a length that is a multiple of four; secrets are
	# routinely stored without the trailing '=', so compute the padding rather
	# than appending a fixed '==' (which would over-pad and break validate=True).
	padded = stripped + "=" * (-len(stripped) % 4)
	try:
		# validate=True rejects any character outside the base64 alphabet
		# instead of silently skipping it; without it, a corrupted key
		# decodes into some other 32 bytes and signs as someone else.
		key_bytes = base64.b64decode(padded, validate=True)
	except (binascii.Error, ValueError) as exc:
		print(f"GLYNDOR_RELEASE_ED25519_KEY is not valid base64: {exc}", file=sys.stderr)
		sys.exit(1)
	# An Ed25519 seed is exactly 32 bytes. from_private_bytes refuses other
	# lengths, but with an opaque error that does not help whoever is
	# debugging a 3 a.m. release. Spell it out here.
	if len(key_bytes) != 32:
		print(
			f"GLYNDOR_RELEASE_ED25519_KEY decoded to {len(key_bytes)} bytes; "
			"an Ed25519 seed must be exactly 32 bytes",
			file=sys.stderr,
		)
		sys.exit(1)
	private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)

	with open(input_file, "rb") as f:
		data = f.read()

	sig = private_key.sign(data)

	with open(sig_file, "wb") as f:
		f.write(sig)

	print(f"signed {input_file} ({len(data):,} bytes) → {sig_file} ({len(sig)} bytes)")


if __name__ == "__main__":
	main()
