//! The `mail` `ports:` array the compose writer pins. Every test
//! here walks an operator-supplied `mail.toml` that already has a
//! `[[listeners]]` array, exercises the apply phase's
//! `ensure_compose_file` entry point, and asserts the rendered
//! publish map matches the non-loopback listeners in the operator's
//! config. Loopback listeners (plain `127.0.0.1` and the
//! IPv4-mapped form) must not be published; non-default ports
//! must keep their number instead of being rounded to the schema
//! default.

use std::fs;

use serde_json::Value;

use super::render;
use super::*;

#[test]
fn mail_published_ports_match_the_listeners_the_config_will_bind() {
	// The previous shape published `993:993` and `465:465`
	// because the IMAPS and Submissions kinds are not written
	// into the config from the answers (`imap` is
	// plaintext-with-STARTTLS, `submission` is STARTTLS), so a
	// compose file that publishes 993 or 465 would forward
	// traffic to a port nothing listens on. With
	// `imap = true` and `submission = true`, the desired
	// config binds smtp(25), imap(143), submission(587) on the
	// dual-stack `::`. Those are exactly the ports the
	// rendered `ports:` array must publish, no more, no less.
	// The test derives the expected list from the listeners
	// init would write (round-tripped through the `Listener`
	// deserialiser) so a future change to the listener set
	// is matched by the publish map without the test having
	// to be edited.
	let value = render(&minimal_answers(), false);
	let ports: Vec<String> = value["services"]["mail"]["ports"]
		.as_array()
		.expect("ports is an array")
		.iter()
		.map(|p| p.as_str().expect("port is a string").to_string())
		.collect();
	// `render` skips the disk; the desired listeners for the
	// minimal answers are smtp, imap, submission (all `::`, no
	// loopback) and the schema defaults are 25, 143, 587.
	let expected: Vec<String> = vec![
		"25:25".to_string(),
		"143:143".to_string(),
		"587:587".to_string(),
	];
	let mut expected_sorted = expected.clone();
	expected_sorted.sort();
	let mut got_sorted = ports.clone();
	got_sorted.sort();
	assert_eq!(
		got_sorted, expected_sorted,
		"published ports must match the listeners in the desired config; \
		 got {ports:?}, expected {expected:?}"
	);
	for port in &ports {
		let (left, right) = port.split_once(':').expect("colon present");
		assert_eq!(
			left, right,
			"published port must be `<p>:<p>`, got {port:?}"
		);
	}
}

/// An operator who already has a listener on a non-default port
/// in the config must see that port in the compose file. The
/// previous `published_ports_for` always emitted the schema
/// default regardless of what the config said, so the compose
/// file would publish a port nothing listened on while the
/// real listener stayed unreachable from the host network.
/// The test compares the compose's `ports` array against the
/// listeners parsed from the on-disk config (the one init
/// actually wrote), not a hard-coded list, so a future change
/// to the listener set is matched by the publish map without
/// the test having to be edited.
#[test]
fn mail_published_ports_reflect_an_operator_listener_on_a_non_default_port() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let mut answers = stack_answers();
	answers.data_dir = data_dir.to_path_buf();
	answers.config_path = data_dir.join("etc").join("mail.toml");
	fs::create_dir_all(data_dir.join("etc")).expect("etc dir");
	// The operator's config pins IMAP to 127.0.0.1:1143 (loopback,
	// unreachable from the host, not published) and a metrics
	// listener on 0.0.0.0:19123 (non-loopback, non-default port,
	// published as 19123:19123). The metrics port is not the
	// schema default (9090), so a regression that always publishes
	// the default would emit 9090:9090 instead.
	let operator_config = "\
		hostname = \"mail.example.org\"\n\
		data_dir = \"/var/lib/epistle\"\n\
		domains = [\"example.org\"]\n\n\
		[tls]\n\
		cert_file = \"/var/lib/epistle/keys/cert.pem\"\n\
		key_file = \"/var/lib/epistle/keys/key.pem\"\n\n\
		[[listeners]]\n\
		kind = \"imap\"\n\
		addr = \"127.0.0.1\"\n\
		port = 1143\n\n\
		[[listeners]]\n\
		kind = \"metrics\"\n\
		addr = \"0.0.0.0\"\n\
		port = 19123\n";
	let path = &answers.config_path;
	let bytes = operator_config.as_bytes().to_vec();
	crate::storage::write_secret(path, &bytes).expect("write config");
	let mut report = crate::cli::init::apply::Report::default();
	ensure_compose_file(&answers, true, &mut report).expect("write compose");
	let compose_text = fs::read_to_string(compose_file_path(data_dir)).expect("read compose");
	let compose: Value = serde_json::from_str(&compose_text).expect("parse compose");
	let ports: Vec<String> = compose["services"]["mail"]["ports"]
		.as_array()
		.expect("ports is an array")
		.iter()
		.map(|p| p.as_str().expect("port is a string").to_string())
		.collect();
	// Parse the listeners the apply phase keeps verbatim and
	// derive the expected `ports` list from those, so a future
	// change to the listener set is matched by the publish map
	// without the test having to be edited.
	let config_text = fs::read_to_string(path).expect("read config");
	let config_value: toml::Value = toml::from_str(&config_text).expect("parse config");
	let mut expected: Vec<String> = Vec::new();
	for entry in config_value
		.get("listeners")
		.and_then(|v| v.as_array())
		.expect("listeners is an array")
	{
		// Round-trip the entry through the real `Listener` deserialiser
		// so the test pins the same shape the apply phase validates
		// against. The hex hand-roll below would diverge if a future
		// `Listener` field becomes mandatory.
		let entry_text = toml::to_string(entry).expect("entry to text");
		let listener: crate::config::Listener =
			toml::from_str(&entry_text).expect("parse listener");
		if listener.addr.is_loopback() {
			continue;
		}
		let port = listener
			.port
			.unwrap_or_else(|| listener.kind.default_port());
		expected.push(format!("{port}:{port}"));
	}
	let mut expected_sorted = expected.clone();
	expected_sorted.sort();
	let mut got_sorted = ports.clone();
	got_sorted.sort();
	assert_eq!(
		got_sorted, expected_sorted,
		"published ports must match the non-loopback listeners in the config init wrote; \
		 got {ports:?}, expected {expected:?}"
	);
	assert!(
		!ports.iter().any(|p| p == "9090:9090"),
		"init must not publish the schema-default metrics port when the operator pinned it; got {ports:?}"
	);
}

/// When the answers turn `services.imap` off but the operator's
/// existing config still carries an `imap` listener, `init` keeps
/// the operator's array verbatim and the compose file must publish
/// the port the operator's listener binds on. The previous
/// `published_ports_for` only looked at the `Services` flags and
/// would have dropped the IMAP publish, so the operator's
/// listener stayed unreachable from the host network after
/// the re-run.
#[test]
fn mail_published_ports_keep_an_operator_listener_even_when_its_service_flag_is_off() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let mut answers = stack_answers();
	answers.data_dir = data_dir.to_path_buf();
	answers.config_path = data_dir.join("etc").join("mail.toml");
	fs::create_dir_all(data_dir.join("etc")).expect("etc dir");
	// The operator's config has an IMAP listener on 0.0.0.0
	// with a non-default port (1143, the schema default is 143),
	// but the answers turn `services.imap` off. Init keeps the
	// operator's listener and the compose file must publish
	// 1143, not 143.
	let operator_config = "\
		hostname = \"mail.example.org\"\n\
		data_dir = \"/var/lib/epistle\"\n\
		domains = [\"example.org\"]\n\n\
		[tls]\n\
		cert_file = \"/var/lib/epistle/keys/cert.pem\"\n\
		key_file = \"/var/lib/epistle/keys/key.pem\"\n\n\
		[[listeners]]\n\
		kind = \"imap\"\n\
		addr = \"0.0.0.0\"\n\
		port = 1143\n";
	let path = &answers.config_path;
	let bytes = operator_config.as_bytes().to_vec();
	crate::storage::write_secret(path, &bytes).expect("write config");
	answers.services.imap = false;
	let mut report = crate::cli::init::apply::Report::default();
	ensure_compose_file(&answers, true, &mut report).expect("write compose");
	let compose_text = fs::read_to_string(compose_file_path(data_dir)).expect("read compose");
	let compose: Value = serde_json::from_str(&compose_text).expect("parse compose");
	let ports: Vec<String> = compose["services"]["mail"]["ports"]
		.as_array()
		.expect("ports is an array")
		.iter()
		.map(|p| p.as_str().expect("port is a string").to_string())
		.collect();
	assert!(
		ports.contains(&"1143:1143".to_string()),
		"the operator's IMAP listener on 0.0.0.0:1143 must be published even when services.imap is off; got {ports:?}"
	);
	assert!(
		!ports.iter().any(|p| p == "143:143"),
		"init must not publish the schema-default IMAP port when the operator pinned it to 1143; got {ports:?}"
	);
}

/// An operator listener on an IPv4-mapped IPv6 loopback
/// (`::ffff:127.0.0.1`, a representation some proxies and
/// language bindings prefer) must be treated as a loopback
/// listener and excluded from the compose `ports:` array.
/// `IpAddr::is_loopback` only recognises `::1`; the canonical
/// form collapses `::ffff:127.0.0.1` to `127.0.0.1`, which the
/// loopback check accepts. Without the canonical form, the
/// listener on `::ffff:127.0.0.1:19123` would be published as
/// `19123:19123`, a port that nothing on the host can reach
/// (the listener only ever sees loopback packets) but that
/// podup would warn about and forward nothing into.
#[test]
fn mail_published_ports_treat_ipv4_mapped_loopback_as_loopback() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let mut answers = stack_answers();
	answers.data_dir = data_dir.to_path_buf();
	answers.config_path = data_dir.join("etc").join("mail.toml");
	fs::create_dir_all(data_dir.join("etc")).expect("etc dir");
	// The operator's config carries a `metrics` listener on the
	// IPv4-mapped loopback `::ffff:127.0.0.1`, port 19123. The
	// address binds only loopback traffic, so the compose file
	// must not publish it; the listener already keeps the
	// metrics endpoint reachable through the pasta mapping.
	// Because the existing config carries a non-empty
	// `listeners` array, the keep-existing-listeners path
	// applies and the only listener the compose file sees is
	// the loopback `metrics` one. With the canonical-form
	// fix in place, the `ports:` array is empty; without
	// the fix it carries `19123:19123`.
	let operator_config = "\
		hostname = \"mail.example.org\"\n\
		data_dir = \"/var/lib/epistle\"\n\
		domains = [\"example.org\"]\n\n\
		[tls]\n\
		cert_file = \"/var/lib/epistle/keys/cert.pem\"\n\
		key_file = \"/var/lib/epistle/keys/key.pem\"\n\n\
		[[listeners]]\n\
		kind = \"metrics\"\n\
		addr = \"::ffff:127.0.0.1\"\n\
		port = 19123\n";
	let path = &answers.config_path;
	let bytes = operator_config.as_bytes().to_vec();
	crate::storage::write_secret(path, &bytes).expect("write config");
	let mut report = crate::cli::init::apply::Report::default();
	ensure_compose_file(&answers, true, &mut report).expect("write compose");
	let compose_text = fs::read_to_string(compose_file_path(data_dir)).expect("read compose");
	let compose: Value = serde_json::from_str(&compose_text).expect("parse compose");
	let ports: Vec<String> = compose["services"]["mail"]["ports"]
		.as_array()
		.expect("ports is an array")
		.iter()
		.map(|p| p.as_str().expect("port is a string").to_string())
		.collect();
	assert!(
		!ports.iter().any(|p| p == "19123:19123"),
		"an IPv4-mapped IPv6 loopback listener must not be published; got {ports:?}"
	);
}

/// A `::1` (plain IPv6) loopback listener is recognised as
/// loopback and excluded from the compose `ports:` array, the
/// shape the `mail_published_ports_match_the_listeners_...`
/// tests pin on for the `127.0.0.1` form. Kept here next to
/// the IPv4-mapped test so the two loopback forms stay
/// covered by the same assertion block.
#[test]
fn mail_published_ports_treat_plain_ipv6_loopback_as_loopback() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path();
	let mut answers = stack_answers();
	answers.data_dir = data_dir.to_path_buf();
	answers.config_path = data_dir.join("etc").join("mail.toml");
	fs::create_dir_all(data_dir.join("etc")).expect("etc dir");
	let operator_config = "\
		hostname = \"mail.example.org\"\n\
		data_dir = \"/var/lib/epistle\"\n\
		domains = [\"example.org\"]\n\n\
		[tls]\n\
		cert_file = \"/var/lib/epistle/keys/cert.pem\"\n\
		key_file = \"/var/lib/epistle/keys/key.pem\"\n\n\
		[[listeners]]\n\
		kind = \"metrics\"\n\
		addr = \"::1\"\n\
		port = 19123\n";
	let path = &answers.config_path;
	let bytes = operator_config.as_bytes().to_vec();
	crate::storage::write_secret(path, &bytes).expect("write config");
	let mut report = crate::cli::init::apply::Report::default();
	ensure_compose_file(&answers, true, &mut report).expect("write compose");
	let compose_text = fs::read_to_string(compose_file_path(data_dir)).expect("read compose");
	let compose: Value = serde_json::from_str(&compose_text).expect("parse compose");
	let ports: Vec<String> = compose["services"]["mail"]["ports"]
		.as_array()
		.expect("ports is an array")
		.iter()
		.map(|p| p.as_str().expect("port is a string").to_string())
		.collect();
	assert!(
		!ports.iter().any(|p| p == "19123:19123"),
		"a ::1 loopback listener must not be published; got {ports:?}"
	);
}
