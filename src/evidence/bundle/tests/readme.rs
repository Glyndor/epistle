//! The README's steps, run with the standard tools it names.

use std::path::{Path, PathBuf};

use super::base::{by_id, exported};
use crate::evidence::audit::tests::base::Fixture;
use crate::evidence::record::{sha256, to_hex};

fn run(bundle: &Path, program: &str, args: &[&str]) -> std::process::Output {
	std::process::Command::new(program)
		.args(args)
		.current_dir(bundle)
		.output()
		.expect("run")
}

/// The README's steps, run with the tools it names.
#[test]
fn the_readme_steps_pass_with_sha256sum_and_openssl() {
	if which("openssl").is_none() || which("sha256sum").is_none() {
		eprintln!("SKIPPED: openssl or sha256sum is not installed");
		return;
	}
	let fixture = Fixture::new();
	let (_out, bundle) = exported(&fixture, &by_id(1));
	let readme = std::fs::read_to_string(bundle.join("README.md")).expect("readme");
	assert!(readme.contains("openssl ts -verify") && readme.contains("sha256sum -c SHA256SUMS"));
	assert!(
		readme.contains("not\n\"correo electronico certificado\"")
			|| readme.contains("\"correo electronico certificado\"")
	);
	let sums = run(&bundle, "sha256sum", &["-c", "SHA256SUMS"]);
	assert!(
		sums.status.success(),
		"{}",
		String::from_utf8_lossy(&sums.stdout)
	);
	let day = "2026-10-15";
	let key = format!("keys/{}.pem", fixture.key.id());
	let signature = run(
		&bundle,
		"openssl",
		&[
			"pkeyutl",
			"-verify",
			"-pubin",
			"-inkey",
			&key,
			"-rawin",
			"-in",
			&format!("checkpoints/{day}.json"),
			"-sigfile",
			&format!("checkpoints/{day}.sig"),
		],
	);
	assert!(
		signature.status.success(),
		"{}",
		String::from_utf8_lossy(&signature.stderr)
	);
	let der = run(
		&bundle,
		"openssl",
		&["pkey", "-pubin", "-in", &key, "-outform", "DER"],
	);
	assert_eq!(
		to_hex(&sha256(&der.stdout)),
		fixture.key.id(),
		"the README's fingerprint is the key id"
	);
	let root = bundle.join("..").join("root.pem");
	std::fs::write(&root, fixture.tsa.root_pem()).expect("root");
	let root = root.to_string_lossy().to_string();
	let stamp = run(
		&bundle,
		"openssl",
		&[
			"ts",
			"-verify",
			"-data",
			&format!("checkpoints/{day}.json"),
			"-in",
			&format!("checkpoints/{day}.tsr"),
			"-CAfile",
			&root,
			"-untrusted",
			&format!("tsa/{day}-chain.pem"),
		],
	);
	assert!(
		stamp.status.success(),
		"{}",
		String::from_utf8_lossy(&stamp.stderr)
	);
	// The same command refuses a checkpoint that was changed.
	std::fs::write(bundle.join(format!("checkpoints/{day}.json")), b"{}").expect("write");
	let refused = run(
		&bundle,
		"openssl",
		&[
			"ts",
			"-verify",
			"-data",
			&format!("checkpoints/{day}.json"),
			"-in",
			&format!("checkpoints/{day}.tsr"),
			"-CAfile",
			&root,
			"-untrusted",
			&format!("tsa/{day}-chain.pem"),
		],
	);
	assert!(!refused.status.success());
}

fn which(program: &str) -> Option<PathBuf> {
	let path = std::env::var_os("PATH")?;
	std::env::split_paths(&path)
		.map(|dir| dir.join(program))
		.find(|candidate| candidate.is_file())
}
