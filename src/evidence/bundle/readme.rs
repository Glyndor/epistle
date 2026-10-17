//! The README of a bundle: how a third party checks it with standard tools.

use std::path::Path;

use super::Exported;

/// Write `README.md` into the bundle at `out`.
pub(super) fn write(out: &Path, exported: &Exported) -> std::io::Result<()> {
	let messages: Vec<String> = exported
		.messages
		.iter()
		.map(|id| format!("- `{id}`"))
		.collect();
	let text = format!(
		r#"# Evidence of sending

This bundle was exported by an epistle mail server. It holds the records
of {records} evidence entries about these messages:

{messages}

It shows that each record below existed, unchanged, when its day was
sealed, and when a timestamp authority stamped that seal. It is not
"correo electronico certificado": it does not come from an ONAC-accredited
entity, and it does not show that anyone read a message. Certificate
revocation (CRL, OCSP) of the timestamp authority is not checked.

## 1. Nothing was changed in transit

    sha256sum -c SHA256SUMS

## 2. The evidence key signed each day's checkpoint

`checkpoints/<day>.json` names the key that signed it (`"key"`): the
SHA-256 of the key's DER form. Do not trust the key file in this bundle on
its word: compare the name with the fingerprint the operator published, which
`epistle evidence check --key` also needs. If the key was rotated, the files
under `keys/rotations/` are statements, each signed by the key it replaces and
naming the day it handed over: a key signs nothing from that day on.

    openssl pkey -pubin -in keys/<key>.pem -outform DER | sha256sum

Then check the signature:

    openssl pkeyutl -verify -pubin -inkey keys/<key>.pem -rawin \
        -in checkpoints/<day>.json -sigfile checkpoints/<day>.sig

## 3. A timestamp authority stamped the checkpoint

`checkpoints/<day>.tsr` is an RFC 3161 response over the SHA-256 of
`checkpoints/<day>.json`. Verify it against the authority's root, which you
obtain yourself (not from this bundle). For Sectigo's public time stamping
service the root is "USERTrust RSA Certification Authority", present in
most operating systems' trust stores:

    openssl ts -verify -data checkpoints/<day>.json -in checkpoints/<day>.tsr \
        -CAfile /etc/ssl/certs/USERTrust_RSA_Certification_Authority.pem \
        -untrusted tsa/<day>-chain.pem

The time it prints is when the authority saw the checkpoint: every record
of that day existed by then.

## 4. Each record is in its day

`records/<day>.jsonl` holds the records, one per line, byte for byte as
written. The SHA-256 of a line (without its newline) is its hash:

    sed -n '1p' records/<day>.jsonl | tr -d '\n' | sha256sum

`proofs/<day>.json` gives, for each line, its position in the day and its
RFC 6962 inclusion proof: the leaf is SHA-256 of 0x00 followed by the line
hash, a node is SHA-256 of 0x01, left, right, and the proof leads to the
`merkle_root` the checkpoint signed. `epistle evidence check <bundle>` runs
all of the above offline, and reports each check by name.

## 5. Nothing contradicts the story

`manifest.json` says what the bundle covers. `epistle evidence check` fails when
a message here lacks its acceptance, or lacks both an abandonment and an
outcome for a recipient the manifest covers: the records are proved one by one,
so this is how a record taken out shows. The bundle says nothing about
messages it does not contain.

## 6. The message itself

When the message was kept, `messages/<id>.eml` holds its exact bytes:
their SHA-256 is the `sha256` of its `accepted` record.

    sha256sum messages/<id>.eml
"#,
		records = exported.records,
		messages = messages.join("\n"),
	);
	super::write_file(&out.join("README.md"), text.as_bytes())
}
