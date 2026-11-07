//! The run that follows an ACME answer: the compose file `init` writes,
//! the directory it leaves alone and the port it publishes.

use serde_json::Value;

use super::acme::answers_minimal;
use super::*;

/// When ACME is on, the compose file's `mail.ports:` array
/// publishes port 80 alongside the other mail ports. Port 80 is
/// the ACME HTTP-01 challenge responder; without the publish, the
/// challenge never reaches the container and certificate issuance
/// silently fails.
///
/// The publish follows the configuration and not the answers: only
/// the HTTP-01 challenge is answered on port 80, so the section the
/// configuration carries has to name it.
#[test]
fn compose_publishes_acme_port_80_when_the_configuration_answers_http_01() {
	use crate::cli::init::compose::{render, stack_answers};
	let dir = tempfile::tempdir().expect("tempdir");
	let mut answers = stack_answers();
	// The stack helper already names a public-ish hostname; force
	// acme on so the test does not depend on the heuristic.
	answers.acme = Some(crate::cli::init::answers::AcmeAnswers {
		enabled: Some(true),
		contact: None,
	});
	answers.config_path = dir.path().join("mail.toml");
	std::fs::write(
		&answers.config_path,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/epistle\"\ndomains = [\"example.org\"]\n\n[acme]\nchallenge = \"http-01\"\n",
	)
	.expect("write config");
	let value: Value = render(&answers, true);
	let ports: Vec<String> = value["services"]["mail"]["ports"]
		.as_array()
		.expect("ports is an array")
		.iter()
		.map(|p| p.as_str().expect("port is a string").to_string())
		.collect();
	assert!(
		ports.contains(&"80:80".to_string()),
		"port 80 must be published when the configuration answers the HTTP-01 challenge so it can reach the responder; got {ports:?}"
	);
}

/// When ACME is on, init leaves `<data_dir>/acme/` empty. The
/// certificate the authority issues lands there and nowhere else, so
/// a bootstrap certificate written there would be read by
/// `crate::acme::renew::needs_renewal` as one valid until the year
/// 4096: no order would ever be placed, and the host would serve
/// the bootstrap forever. The server serves the self-signed pair in
/// `keys/` until the authority answers.
#[test]
fn apply_leaves_the_acme_path_without_a_bootstrap_certificate() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	// Public hostname: ACME auto-enables on a fresh install.
	let outcome = apply(&answers);
	assert!(
		outcome.error.is_none(),
		"apply must succeed with ACME auto-enabled; got {:?}",
		outcome.error
	);
	let acme_cert = data_dir.join("acme").join("cert.pem");
	let acme_key = data_dir.join("acme").join("key.pem");
	for path in [&acme_cert, &acme_key] {
		assert!(
			!path.exists(),
			"init must not leave a bootstrap certificate at {}; a certificate nobody vouches \
			 for reads as valid until the year 4096, so the first boot would never ask \
			 the authority for the real one",
			path.display()
		);
	}
	// The pair the server serves until the authority answers is the
	// one in `keys/`, and it is on disk.
	let keys_cert = data_dir.join("keys").join("cert.pem");
	let keys_key = data_dir.join("keys").join("key.pem");
	for path in [&keys_cert, &keys_key] {
		assert!(
			path.exists(),
			"init must write the bootstrap pair at {}; the server serves it until the \
			 authority answers",
			path.display()
		);
	}
}

/// When ACME is off, init does not create `<data_dir>/acme/` at
/// all. The keys/ path is what the server loads; the ACME path is
/// only relevant when ACME is on.
#[test]
fn apply_does_not_create_the_acme_directory_when_acme_is_off() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.hostname = "mail.example.local".to_string();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(
		outcome.error.is_none(),
		"apply must succeed with ACME off; got {:?}",
		outcome.error
	);
	let acme_dir = data_dir.join("acme");
	assert!(
		!acme_dir.exists(),
		"apply must not create <data_dir>/acme when ACME is off; got {}",
		acme_dir.display()
	);
}

/// When ACME is off, port 80 is not published. The compose writer
/// derives the published-port list from the listener set init just
/// wrote, so the absence of the `acme` listener in the config is
/// what keeps 80 out of the publish map. A regression that always
/// published 80 would forward traffic to a closed socket for every
/// install that runs without ACME.
#[test]
fn compose_does_not_publish_acme_port_80_when_acme_is_off() {
	use crate::cli::init::compose::{render, stack_answers};
	let mut answers = stack_answers();
	answers.hostname = "mail.example.local".to_string();
	answers.acme = Some(crate::cli::init::answers::AcmeAnswers {
		enabled: Some(false),
		contact: None,
	});
	let value: Value = render(&answers, true);
	let ports: Vec<String> = value["services"]["mail"]["ports"]
		.as_array()
		.expect("ports is an array")
		.iter()
		.map(|p| p.as_str().expect("port is a string").to_string())
		.collect();
	assert!(
		!ports.contains(&"80:80".to_string()),
		"port 80 must not be published when ACME is off; got {ports:?}"
	);
}

/// The compose file the apply phase writes publishes port 80 when the
/// configuration it wrote answers the HTTP-01 challenge. The config
/// comes first, so the `[acme]` section is already on disk when the
/// publish list is derived from it.
#[test]
fn the_compose_the_apply_phase_writes_publishes_port_80_for_http_01() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut answers = answers_minimal();
	answers.data_dir = dir.path().join("data");
	answers.config_path = dir.path().join("mail.toml");
	// A public hostname: init writes the `[acme]` section, and the
	// challenge it leaves unset is the HTTP-01 one.
	let outcome = apply(&answers);
	assert!(
		outcome.error.is_none(),
		"apply must succeed with ACME auto-enabled; got {:?}",
		outcome.error
	);
	let compose = std::fs::read_to_string(answers.data_dir.join("compose/compose.yaml"))
		.expect("read compose");
	let document: Value = serde_json::from_str(&compose).expect("parse compose");
	let ports: Vec<String> = document["services"]["mail"]["ports"]
		.as_array()
		.expect("ports is an array")
		.iter()
		.map(|p| p.as_str().expect("port is a string").to_string())
		.collect();
	assert!(
		ports.contains(&"80:80".to_string()),
		"the HTTP-01 challenge is answered on port 80, so the compose file must publish it; got {ports:?}"
	);
}
