//! `epistle dkim-keygen --rsa` must not need `openssl` on `PATH`.
//!
//! The image the stack runs (`gcr.io/distroless/static-debian12:nonroot`)
//! ships no `openssl`, and the first DKIM rotation of a fresh install
//! failed there for that reason (Glyndor/epistle#1376): the key was made
//! by shelling out to `openssl genpkey`. The key is made in process now,
//! so the command works with nothing on `PATH`.
//!
//! The child gets a `PATH` pointing at an empty directory, so an
//! `openssl` binary cannot be found there even when the host has one.

use std::process::Command;

#[test]
fn dkim_keygen_rsa_works_without_openssl_on_path() {
	let dir = tempfile::tempdir().expect("tempdir");
	let empty_path = dir.path().join("empty-path");
	std::fs::create_dir(&empty_path).expect("an empty directory to use as PATH");
	let out = dir.path().join("rsa.pem");
	let output = Command::new(env!("CARGO_BIN_EXE_epistle"))
		.args(["dkim-keygen", "--rsa", "--out"])
		.arg(&out)
		.env("PATH", &empty_path)
		.output()
		.expect("run dkim-keygen");
	assert!(
		output.status.success(),
		"dkim-keygen --rsa must not need openssl: stdout={} stderr={}",
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	);
	let pem = std::fs::read_to_string(&out).expect("the key was written");
	assert!(
		pem.starts_with("-----BEGIN PRIVATE KEY-----"),
		"a PKCS#8 PEM was written: {pem}"
	);
	let stdout = String::from_utf8_lossy(&output.stdout);
	assert!(
		stdout.contains("v=DKIM1; k=rsa; p="),
		"the record to publish is printed: {stdout}"
	);
}
