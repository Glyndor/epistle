# External DKIM and ARC fixtures

Regenerate from this checkout with:

```sh
python3 -I tests/fixtures/dkim/generate
```

The generator requires Python `cryptography` (generated with 46.0.5), uses fixed
private keys checked into this directory, and never calls the project signer.
These are public test keys. Do not use them for real messages or DNS.
RSA-2048 and RSA-1024 keys were generated with Python cryptography; the RSA-512
key was constructed with its RSA private-number API. Key generation is not part
of regeneration. Ed25519 uses a fixed test seed. `ed25519-ring.pem` contains the
same key in PKCS8 v2, including its public key, as required by the project loader.

The generator has no extension because the repository's test-discovery guard
classifies all `.py` files under `tests/` as separate tests requiring a workflow.
This script is a fixture generator, not another test runner. Rust tests read the
committed outputs and require neither Python nor an external DNS server.

`rfc8463.eml`, `rfc8463.input`, and `rfc8463.dns` are immutable external inputs,
transcribed from `src/dkim/verify/tests/ed25519.rs`, whose source is RFC 8463
Appendix A. The RSA signature printed by that RFC is omitted. Python verifies
the published Ed25519 signature over SHA-256 and asserts literal canonicalization
outputs and empty-body hashes from RFC 6376 sections 3.4.3 through 3.4.5.

Every generated signature is checked with cryptography's public-key API before
writing. Deliberately crossed algorithms are checked with the actual primitive
that created the attack, not the advertised algorithm. `manifest.json` records
each generated message digest, canonicalization, canonical body, and signing
input digest where applicable. `signer-*.signature`, `.unsigned`, and `.input`
are independent expected outputs for testing production signing.

Messages use CRLF bytes. Preserve them when editing or checking out this tree.
`*.dns` contains TXT data only. ARC uses separate `ams` and `seal` selectors.
Malformed syntax, bit changes, duplicate fields, and resource probes are built
from these fixtures by the Rust tests. The short and zero `l=` fullhash vectors
are deliberately inconsistent DKIM inputs: their hash covers the full body,
so removing the explicit length check cannot be masked by a body-hash mismatch.

## Preserved develop vectors

The `tags-*` files and `tags-manifest.json` belong to the tag-list regression
suite already present in develop. They are preserved separately from the 57
messages in `manifest.json`; `generate` does not regenerate the tag-list suite.
The Rust target is `hostile_dkim`, rooted at `tests/dkim/hostile_dkim.rs`.
