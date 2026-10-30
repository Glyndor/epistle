//! The certificate a fresh install serves, and the decision the
//! renewal loop takes on it.
//!
//! The flow is the one an operator with a DNS provider follows:
//! `init` in automatic mode with a `[dns]` section, so the config
//! carries the provider the dns-01 challenge needs, and then the
//! operator switches the challenge to `dns-01` by hand.
//!
//! What the test pins is the first boot: it has to ask the
//! authority for the real certificate. A bootstrap certificate the
//! renewal loop reads as current (`notAfter` in the year 4096) means
//! no order is ever placed, and the host serves the bootstrap
//! forever.

use std::path::Path;
#[cfg(unix)]
use std::process::{Command, Stdio};

#[cfg(unix)]
use super::helpers::{binary, write_answers};

/// Answers for the flow the issue describes: automatic mode with a
/// `[dns]` provider, a public hostname so `init` writes the `[acme]`
/// block, and no database so the run stays local.
#[cfg(unix)]
fn dns01_answers_body(data_dir: &Path, config_path: &Path) -> String {
	format!(
		"mode = \"automatic\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 public_ipv4 = \"8.8.8.8\"\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\
		 image = \"localhost/epistle:dev\"\n\n\
		 [dns]\n\
		 provider = \"cloudflare\"\n\
		 zone = \"example.org\"\n\
		 token_env = \"EPISTLE_TEST_DNS_TOKEN\"\n\n\
		 [services]\n\
		 database = false\n",
		data_dir.display(),
		config_path.display(),
	)
}

/// Run the binary and return its exit code and stderr.
#[cfg(unix)]
fn run(args: &[&str]) -> (Option<i32>, String) {
	let mut cmd = Command::new(binary());
	cmd.args(args);
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	(
		output.status.code(),
		String::from_utf8_lossy(&output.stderr).into_owned(),
	)
}

/// The `cert_file` the generated config points at.
#[cfg(unix)]
fn tls_cert_file(config: &str) -> String {
	let value: toml::Value = toml::from_str(config).expect("config parses");
	value
		.get("tls")
		.and_then(|tls| tls.get("cert_file"))
		.and_then(|path| path.as_str())
		.expect("config carries [tls] cert_file")
		.to_string()
}

/// A fresh install with ACME on must be ready to ask the authority
/// for its certificate on the first boot.
///
/// Three things have to hold together: the server comes up (the
/// certificate the config names is on disk), the config the operator
/// edits for dns-01 still validates, and the renewal loop finds
/// nothing current at the ACME path, so it places an order instead
/// of waiting for a certificate that will never be replaced.
#[cfg(unix)]
#[test]
fn a_fresh_install_asks_for_its_first_certificate() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	let answers = write_answers(
		dir.path(),
		"answers.toml",
		&dns01_answers_body(&data_dir, &config_path),
	);
	let (code, stderr) = run(&["init", "--answers", answers.to_str().unwrap()]);
	assert_eq!(code, Some(0), "init must succeed; stderr: {stderr}");

	let config = std::fs::read_to_string(&config_path).expect("read config");
	// The operator switches the challenge to dns-01 by hand, the way
	// the issue describes.
	assert!(
		config.contains("[acme]"),
		"init must write the [acme] block for a public hostname; config: {config}"
	);
	assert!(
		config.contains("[dns]"),
		"init must write the [dns] section the dns-01 challenge needs; config: {config}"
	);
	let edited = config.replace("[acme]\n", "[acme]\nchallenge = \"dns-01\"\n");
	std::fs::write(&config_path, &edited).expect("write config");
	let (code, stderr) = run(&["config-check", "--config", config_path.to_str().unwrap()]);
	assert_eq!(
		code,
		Some(0),
		"the dns-01 config must validate; stderr: {stderr}"
	);

	// The certificate the config names has to be on disk: the server
	// comes up before the authority has answered anything.
	let cert_file = tls_cert_file(&edited);
	assert!(
		Path::new(&cert_file).is_file(),
		"the certificate the config names must exist so the server starts; {cert_file}"
	);

	// And the renewal loop must find nothing current at the ACME
	// path, so the first boot places an order. A bootstrap
	// certificate that reads as valid until the year 4096 leaves the
	// host on it forever.
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs();
	assert!(
		epistle::acme::renew::needs_renewal(&data_dir, 30, now),
		"the first boot must ask the authority for the real certificate; the certificate at \
		 <data_dir>/acme/cert.pem reads as current, so no order is ever placed"
	);
}
