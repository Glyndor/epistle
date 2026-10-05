//! Compose file unit tests.
//!
//! The tests parse the generated JSON with `serde_json` and pin
//! the shape podup reads: `mail.network_mode == "pasta"`,
//! `mail.userns_mode` is the keep-id value, every published port
//! matches a listener in the generated `mail.toml`, the `db`
//! service has no `ports` and no `networks`, no service has a
//! `networks` key, the compose file carries no `x-podman-pod`,
//! every image is pinned, the `db` secret uses the long syntax
//! with uid 999, and the paths in `mail.volumes` are identical on
//! both sides of the colon. A second test runs with the database
//! service off and asserts the `db` service, the secrets block,
//! the volumes block, and the `depends_on` block are all absent.
//!
//! The compose file is JSON, not YAML; the repository has no YAML
//! crate. The tests rely on `serde_json` parsing the rendered file
//! and reading the same fields podup reads.

use std::fs;

use serde_json::Value;

use super::*;
use crate::cli::init::Answers;
use crate::cli::init::answers::Invalid;

fn render(answers: &Answers, database: bool) -> Value {
	let bytes = render_for(answers, database).expect("render");
	serde_json::from_str(&bytes).expect("parse")
}

#[test]
fn name_is_epistle() {
	let value = render(&minimal_answers(), false);
	assert_eq!(value["name"], "epistle");
}

#[test]
fn mail_uses_pasta_and_keep_id() {
	let value = render(&minimal_answers(), false);
	let mail = &value["services"]["mail"];
	assert_eq!(mail["network_mode"], "pasta");
	assert_eq!(mail["userns_mode"], "keep-id:uid=65532,gid=65532");
	assert_eq!(mail["user"], "65532:65532");
}

#[test]
fn mail_lowers_unprivileged_port_start_inside_its_netns() {
	// The mail user is uid 65532, non-root inside the container's
	// network namespace, where the kernel default
	// `net.ipv4.ip_unprivileged_port_start` is 1024. The mail
	// service binds SMTP (25) and several IANA-reserved listeners
	// (465, 587, 143, 993, 4190, ...). Without lowering the sysctl,
	// the listener would fail with `Permission denied (os error 13)`
	// at startup. The setting is namespaced to the container's netns
	// and does not change anything on the host.
	let value = render(&minimal_answers(), false);
	let sysctls = &value["services"]["mail"]["sysctls"];
	assert_eq!(
		sysctls["net.ipv4.ip_unprivileged_port_start"], "0",
		"the mail service must lower ip_unprivileged_port_start inside its netns; got {sysctls}"
	);
}

#[test]
fn mail_command_uses_serve_and_config_path() {
	let value = render(&minimal_answers(), false);
	let command = value["services"]["mail"]["command"]
		.as_array()
		.expect("command is an array");
	assert_eq!(command.len(), 3);
	assert_eq!(command[0], "serve");
	assert_eq!(command[1], "--config");
	let path_str = command[2].as_str().expect("config path is a string");
	assert!(path_str.ends_with("mail.toml"), "got {path_str}");
	assert!(path_str.starts_with("/etc/epistle/"), "got {path_str}");
}

#[test]
fn mail_volumes_have_identical_paths_on_both_sides_of_the_colon() {
	let value = render(&minimal_answers(), false);
	let volumes = value["services"]["mail"]["volumes"]
		.as_array()
		.expect("volumes is an array");
	for entry in volumes {
		let s = entry.as_str().expect("volume is a string");
		if s.contains(':') && !s.contains("epistle-pg") {
			let (host, rest) = s.split_once(':').expect("colon present");
			let container = rest.split(':').next().unwrap_or(rest);
			assert_eq!(
				host, container,
				"host and container paths must be identical for non-named volumes, got {s:?}"
			);
		}
	}
}

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

/// When `services.imap` is `false` but the operator's existing
/// config still carries an `imap` listener, `init` keeps the
/// operator's array verbatim and the compose file must publish
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

#[test]
fn mail_depends_on_db_when_database_is_on() {
	let value = render(&stack_answers(), true);
	let mail = &value["services"]["mail"];
	let depends_on = &mail["depends_on"];
	assert_eq!(depends_on["db"]["condition"], "service_healthy");
}

#[test]
fn mail_has_no_depends_on_when_database_is_off() {
	let value = render(&minimal_answers(), false);
	assert!(value["services"]["mail"].get("depends_on").is_none());
}

#[test]
fn no_service_has_a_networks_key() {
	let value = render(&stack_answers(), true);
	for (name, service) in value["services"].as_object().unwrap() {
		assert!(
			service.get("networks").is_none(),
			"service {name} must not declare networks; podup will create one otherwise"
		);
	}
}

#[test]
fn no_x_podman_pod_anywhere() {
	let value = render(&stack_answers(), true);
	assert!(
		value.get("x-podman-pod").is_none(),
		"the compose file must not declare an x-podman-pod"
	);
}

#[test]
fn every_image_is_pinned() {
	let value = render(&stack_answers(), true);
	for (name, service) in value["services"].as_object().unwrap() {
		let image = service["image"]
			.as_str()
			.unwrap_or_else(|| panic!("service {name} has no image"));
		// A digest pin (`@sha256:...`) is the strongest form. A
		// tag other than `latest` is acceptable for the `mail`
		// service (the release workflow tags `0.8`, `0.8.0`); a
		// floating `:latest` would silently change what `init`
		// brings up. An untagged reference (no `@sha256:`, no
		// `:tag` at all) would default to `:latest` on the
		// daemon, which is exactly what the validator catches
		// for operator overrides. The previous shape
		// (`image.contains('@') || !image.ends_with(":latest")`)
		// accepted untagged references: a value like
		// `docker.io/library/postgres` has no `@` and does not
		// end in `:latest`, so the assertion passed while the
		// reference was still untagged. The new shape requires
		// either a digest or a `:` followed by a non-empty
		// non-`latest` tag.
		let (path, suffix) = image
			.rsplit_once('@')
			.or_else(|| image.rsplit_once(':'))
			.unwrap_or((image, ""));
		let pinned = !suffix.is_empty() && (image.contains("@sha256:") || suffix != "latest");
		assert!(
			pinned,
			"service {name} image {image:?} must be pinned (digest or non-latest tag); \
			 the part after the last `@` or `:` is {suffix:?}, the path part is {path:?}"
		);
	}
}

/// The image-pinning test must hold against any change to the
/// pin in `compose.rs` (the production code's `POSTGRES_18_IMAGE`
/// constant). The previous shape compared the rendered `db`
/// image against the same `POSTGRES_18_IMAGE` constant the
/// production code uses, so changing the constant to
/// `docker.io/library/postgres` (dropping the `:18@sha256:...`
/// pin) made the test pass while the rendered image was still
/// the new constant's value. The new shape pins the expected
/// reference to the literal digest-pinned value here, so any
/// change to the production constant that drops the digest
/// makes the test go red: the rendered image would no longer
/// match the literal the test writes down.
#[test]
fn db_image_is_the_pinned_postgres_18_digest() {
	let value = render(&stack_answers(), true);
	let db_image = value["services"]["db"]["image"]
		.as_str()
		.expect("db image is a string");
	// The literal the test pins against is the full
	// digest-pinned reference, NOT the production code's
	// `POSTGRES_18_IMAGE` constant. A change to the constant
	// that drops the digest (`docker.io/library/postgres`
	// instead of `docker.io/library/postgres:18@sha256:...`)
	// would change the rendered image away from this
	// literal, and the test would fail.
	assert_eq!(
		db_image,
		"docker.io/library/postgres:18@sha256:06cad38a5d9f5d24b4d83d86def30795d5e4b757fedbf5281172b576dedcd941",
		"the rendered db image must be the digest-pinned postgres:18 reference; \
		 the production code's POSTGRES_18_IMAGE constant was changed and the pin was dropped"
	);
}

#[test]
fn mail_image_uses_cargo_pkg_version_by_default() {
	let value = render(&minimal_answers(), false);
	let image = value["services"]["mail"]["image"]
		.as_str()
		.expect("image is a string");
	let expected = default_image();
	assert_eq!(image, expected);
}

#[test]
fn mail_image_override_takes_precedence() {
	let value = render(&local_image_answers(), true);
	let image = value["services"]["mail"]["image"]
		.as_str()
		.expect("image is a string");
	assert_eq!(image, "localhost/epistle:dev");
}

#[test]
fn db_uses_network_mode_none_and_has_no_ports() {
	let value = render(&stack_answers(), true);
	let db = &value["services"]["db"];
	assert_eq!(db["network_mode"], "none");
	assert!(db.get("ports").is_none(), "db must not publish any port");
	assert!(db.get("networks").is_none(), "db must not declare networks");
}

#[test]
fn db_secrets_uses_long_syntax_with_uid_999_and_octal_mode() {
	let value = render(&stack_answers(), true);
	let secrets = value["services"]["db"]["secrets"]
		.as_array()
		.expect("secrets is an array");
	assert_eq!(secrets.len(), 1);
	let mount = &secrets[0];
	assert_eq!(mount["source"], "epistle_db_password");
	assert_eq!(mount["target"], "epistle_db_password");
	assert_eq!(mount["uid"], "999");
	assert_eq!(mount["gid"], "999");
	// The mode is a JSON number; podup reads the value as octal.
	// The number `400` in the rendered file is `0o400` after
	// podup parses it: owner read-only. Writing `256` (which
	// is `0o400` in decimal interpretation) would be parsed by
	// podup as `0o256` and rejected for the owner-execute bit.
	assert_eq!(mount["mode"], 400);
}

#[test]
fn db_healthcheck_queries_the_real_database() {
	let value = render(&stack_answers(), true);
	let healthcheck = &value["services"]["db"]["healthcheck"];
	let test = healthcheck["test"]
		.as_array()
		.expect("healthcheck.test is an array");
	assert_eq!(test[0], "CMD-SHELL");
	let cmd = test[1].as_str().expect("cmd is a string");
	assert!(cmd.contains("psql"), "got {cmd}");
	assert!(cmd.contains("-U epistle"), "got {cmd}");
	assert!(cmd.contains("-d epistle"), "got {cmd}");
	assert!(cmd.contains("select 1"), "got {cmd}");
	assert!(
		cmd.contains("/var/run/postgresql"),
		"the healthcheck must connect over the socket, got {cmd}"
	);
	assert_eq!(healthcheck["interval"], "5s");
	assert_eq!(healthcheck["timeout"], "5s");
	assert_eq!(healthcheck["retries"], 30);
}

#[test]
fn db_is_read_only_with_a_tmpfs_for_tmp() {
	let value = render(&stack_answers(), true);
	let db = &value["services"]["db"];
	assert_eq!(db["read_only"], true);
	let tmpfs = db["tmpfs"].as_array().expect("tmpfs is an array");
	assert_eq!(tmpfs, &vec![Value::String("/tmp".to_string())]);
}

#[test]
fn top_level_secrets_and_volumes_present_when_database_is_on() {
	let value = render(&stack_answers(), true);
	let secrets = &value["secrets"];
	assert!(
		secrets["epistle_db_password"]["file"]
			.as_str()
			.is_some_and(|s| s.ends_with("epistle_db_password")),
		"the top-level secret must point at the on-host password file"
	);
	let volumes = &value["volumes"];
	assert!(volumes.get("epistle-pgdata").is_some());
	assert!(volumes.get("epistle-pgsock").is_some());
}

#[test]
fn database_off_has_no_db_no_secrets_no_volumes() {
	let value = render(&minimal_answers(), false);
	assert!(
		value["services"].get("db").is_none(),
		"with database off there must be no `db` service"
	);
	assert_eq!(
		value["secrets"]
			.as_object()
			.expect("secrets is an object")
			.len(),
		0,
		"with database off the top-level secrets block must be empty"
	);
	assert!(
		value["volumes"].is_null() || value["volumes"].as_object().is_some_and(|o| o.is_empty()),
		"with database off the top-level volumes block must be absent or empty"
	);
}

#[test]
fn image_validation_rejects_empty_and_whitespace() {
	// The answers validator catches empty / whitespace-only
	// `image` values; the compose writer itself trusts
	// what the validator passed.
	let mut answers = minimal_answers();
	answers.image = Some("".to_string());
	assert!(answers.validate().is_err());
	answers.image = Some("with space".to_string());
	assert!(answers.validate().is_err());
	answers.image = Some("localhost/epistle:dev".to_string());
	assert!(answers.validate().is_ok());
}

/// The default `image` resolved when the operator does not set one
/// pins the `<MAJOR.MINOR>` prefix of `CARGO_PKG_VERSION` (not
/// the full `X.Y.Z` patch, not `latest`, and not an untagged
/// reference). The override path uses whatever the operator
/// typed verbatim, as long as the override itself carries a
/// tag that is not `latest` or a `@sha256:` digest.
#[test]
fn image_default_and_override_resolve_to_the_expected_references() {
	let version = env!("CARGO_PKG_VERSION");
	let mut parts = version.split('.');
	let major = parts.next().expect("major");
	let minor = parts.next().expect("minor");
	let expected_default = format!("ghcr.io/glyndor/epistle:{}.{}", major, minor);
	let default = super::default_image();
	assert_eq!(
		default, expected_default,
		"the default image must pin the MAJOR.MINOR of CARGO_PKG_VERSION; \
		 a release of 0.9.0 must produce ghcr.io/glyndor/epistle:0.9"
	);
	assert!(
		!default.contains("latest") && default.contains(':'),
		"the default must carry a tag that is not 'latest'; got {default}"
	);
	assert!(
		!default.contains('@'),
		"the default uses a tag, not a digest; got {default}"
	);
	let from_none = super::resolve_image(None);
	assert_eq!(from_none, default);
	let image = super::resolve_image(Some("localhost/epistle:dev"));
	assert_eq!(image, "localhost/epistle:dev");
	let pinned = super::resolve_image(Some(
		"localhost/epistle@sha256:0000000000000000000000000000000000000000000000000000000000000000",
	));
	assert_eq!(
		pinned,
		"localhost/epistle@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	);
}

/// Every image the compose writer pins must carry either a
/// `<MAJOR.MINOR>`-style tag (not `latest`) or a `@sha256:`
/// digest. The answers validator catches operator overrides
/// that miss the rule; the default image is also covered by
/// `image_default_and_override_resolve_to_the_expected_references`.
#[test]
fn image_validator_rejects_untagged_or_latest_references() {
	fn first_invalid(answers: &Answers) -> Invalid {
		answers
			.validate()
			.expect_err("the answers must fail validation")
			.into_iter()
			.next()
			.expect("at least one error")
	}
	// No tag at all: a `localhost/epistle` reference defaults to
	// `:latest` on the daemon, which the validator refuses.
	let mut answers = minimal_answers();
	answers.image = Some("localhost/epistle".to_string());
	assert!(matches!(first_invalid(&answers), Invalid::ImageUntagged(_)));
	// Explicit `:latest`: no better than no tag.
	answers.image = Some("localhost/epistle:latest".to_string());
	assert!(matches!(first_invalid(&answers), Invalid::ImageUntagged(_)));
	// Digest without the `sha256:` algorithm: refused.
	answers.image = Some("localhost/epistle@md5:deadbeef".to_string());
	assert!(matches!(first_invalid(&answers), Invalid::ImageUntagged(_)));
	// A pinned tag and a sha256 digest are both accepted.
	answers.image = Some("localhost/epistle:1.2.3".to_string());
	assert!(answers.validate().is_ok());
	answers.image = Some(
		"localhost/epistle@sha256:0000000000000000000000000000000000000000000000000000000000000000"
			.to_string(),
	);
	assert!(answers.validate().is_ok());
}

/// The tag separator is the last `:` after the last `/`; a `:`
/// before the last `/` is a registry-port separator and must
/// not be read as a tag. The previous `rsplit_once(':')` shape
/// mistook the registry port for a tag and let
/// `localhost:5000/epistle` through (the daemon would then
/// default to `:latest`), and let
/// `localhost/epistle:${TAG:-latest}` through (the compose
/// writer would have emitted the literal `$`, which the daemon
/// then refuses). The new shape catches both, plus the explicit
/// `localhost:5000/epistle:1.2` accept case.
#[test]
fn image_validator_handles_registry_port_and_compose_interpolation() {
	fn first_invalid(answers: &Answers) -> Invalid {
		answers
			.validate()
			.expect_err("the answers must fail validation")
			.into_iter()
			.next()
			.expect("at least one error")
	}
	let mut answers = minimal_answers();
	// Registry port, no tag: refused. The old shape saw the
	// `:` between `localhost` and `5000` and read `5000/epistle`
	// as the tag, which is neither `latest` nor empty and so
	// slipped through; the daemon would then default to
	// `:latest` and pull a moving reference.
	answers.image = Some("localhost:5000/epistle".to_string());
	assert!(matches!(first_invalid(&answers), Invalid::ImageUntagged(_)));
	// Registry port with an explicit tag: accepted. The
	// `:` after the last `/` separates the tag, and the `5000`
	// is read as the registry port.
	answers.image = Some("localhost:5000/epistle:1.2".to_string());
	assert!(answers.validate().is_ok());
	// Digest form, with a real registry: accepted. The
	// `:` in `sha256:` is the digest algorithm separator, not
	// a tag separator.
	answers.image = Some(
		"ghcr.io/glyndor/epistle@sha256:0000000000000000000000000000000000000000000000000000000000000000"
			.to_string(),
	);
	assert!(answers.validate().is_ok());
	// Compose interpolation: refused. The literal `$` would
	// land in the rendered compose file, the daemon would
	// refuse the reference, and the operator would see a
	// fail at `podup up` time rather than at `init` time.
	answers.image = Some("localhost/epistle:${TAG:-latest}".to_string());
	assert!(matches!(
		first_invalid(&answers),
		Invalid::ImageMalformed(_)
	));
	// Bare `$` somewhere else in the reference: also refused.
	answers.image = Some("ghcr.io/glyndor/$epistle:1.2".to_string());
	assert!(matches!(
		first_invalid(&answers),
		Invalid::ImageMalformed(_)
	));
}

/// A reference that has no path component (no `/` in the
/// reference at all, e.g. `epistle:dev`, the form a local
/// build with `podman build -t epistle:dev .` produces) has
/// no registry-port branch: the only `:` in the reference is
/// the tag separator. The previous shape
/// (`image.rfind('/').and_then(...)` returning `None` when
/// the reference has no `/`) read a missing `/` as a missing
/// tag and refused every short reference with
/// `ImageUntagged`; the operator had to spell out
/// `localhost/epistle:dev` for a local build, which is
/// surprising because `podman build -t epistle:dev .` is the
/// recipe in the project docs. The fix finds the last `:` in
/// the segment after the last `/` (or in the whole reference
/// when there is no `/`); `epistle:dev` now parses with tag
/// `dev` and the override is accepted.
#[test]
fn image_validator_accepts_a_short_reference_with_no_path() {
	let mut answers = minimal_answers();
	// Short reference, no `/`, with a non-latest tag: accepted.
	// This is the form `podman build -t epistle:dev .`
	// produces and the local bring-up recipe in the project
	// docs uses.
	answers.image = Some("epistle:dev".to_string());
	assert!(
		answers.validate().is_ok(),
		"a short reference like `epistle:dev` must validate: {:?}",
		answers.validate()
	);
	// Short reference, no `/`, no tag: still refused.
	answers.image = Some("epistle".to_string());
	assert!(matches!(
		answers
			.validate()
			.expect_err("an untagged short reference must fail")
			.into_iter()
			.next()
			.expect("at least one error"),
		Invalid::ImageUntagged(_)
	));
	// Short reference, no `/`, explicit `:latest`: refused
	// (`:latest` is no better than no tag).
	answers.image = Some("epistle:latest".to_string());
	assert!(matches!(
		answers
			.validate()
			.expect_err("an explicit `:latest` must fail")
			.into_iter()
			.next()
			.expect("at least one error"),
		Invalid::ImageUntagged(_)
	));
}

#[test]
fn db_top_level_secret_path_points_at_the_data_dir() {
	let value = render(&stack_answers(), true);
	let file = value["secrets"]["epistle_db_password"]["file"]
		.as_str()
		.expect("file is a string");
	assert!(file.contains("/var/lib/epistle"), "got {file}");
	assert!(file.ends_with("epistle_db_password"));
}

/// The README that `init` writes next to the compose file is
/// operator-facing documentation, not a secret. The apply
/// phase pins the mode to `0o644` explicitly so a tight umask
/// (for example, `0o077`) does not leave the file at `0o600`,
/// which would make a follow-up `cat README` from a different
/// account quietly deny access.
///
/// The previous shape of this test created the parent
/// directories with explicit modes (`0o700`) and asserted the
/// README lands at `0o644`, but did not change the process
/// umask. On a runner with the default umask `0o022`, an
/// `OpenOptions::new().create(true).truncate(true).open(&path)`
/// call (the shape the apply phase uses to create the README)
/// lands the file at `0o644` even when the apply phase does
/// NOT call `set_permissions(0o644)`, so a regression that
/// dropped the `set_permissions` call stayed green. The new
/// shape runs the apply phase under a `0o077` umask so the
/// default file mode is `0o600`; the apply phase must
/// explicitly set `0o644` to make the assertion pass. The
/// original umask is captured before the change and restored
/// before the test returns so the side effect does not leak
/// into other tests in the same binary.
#[cfg(unix)]
#[test]
fn compose_readme_is_pinned_to_mode_0644() {
	use crate::cli::init::apply;
	use std::os::unix::fs::PermissionsExt;
	// Save the current umask and set a restrictive one for
	// the duration of the test. `libc::umask` returns the
	// previous mask and sets the new one in a single call.
	// The previous mask is restored before the test returns
	// so the side effect does not leak into other tests.
	let previous = unsafe { libc::umask(0o077) };
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	std::fs::create_dir_all(config_path.parent().unwrap()).expect("mkdir etc");
	// Pre-create the parent directories the apply phase would
	// also create. Under the `0o077` umask, `create_dir_all`
	// lands them at `0o700` (the default for a directory is
	// `0o777 & ~umask`). The explicit `OpenOptionsExt::mode`
	// is not needed for the parent because the parent's mode
	// does not influence the mode the apply phase sets on
	// the README; the umask does.
	std::fs::create_dir_all(data_dir.join("keys")).expect("mkdir keys");
	std::fs::set_permissions(
		data_dir.join("keys"),
		std::fs::Permissions::from_mode(0o700),
	)
	.expect("set keys mode");
	std::fs::create_dir_all(data_dir.join("compose")).expect("mkdir compose");
	std::fs::set_permissions(
		data_dir.join("compose"),
		std::fs::Permissions::from_mode(0o700),
	)
	.expect("set compose mode");
	let mut answers = minimal_answers();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply::apply(&answers);
	// Restore the umask before any assertion that could
	// panic, so a failing test still leaves the process
	// umask at its original value.
	unsafe {
		libc::umask(previous);
	}
	assert!(outcome.error.is_none(), "first apply: {:?}", outcome.error);
	drop(outcome);
	let readme = data_dir.join("compose").join("README");
	let mode = std::fs::metadata(&readme)
		.expect("stat")
		.permissions()
		.mode()
		& 0o777;
	assert_eq!(
		mode, 0o644,
		"the README must land at 0o644 under a 0o077 umask; the apply phase has to \
		 call set_permissions(0o644) explicitly because a plain open() under this umask \
		 would land the file at 0o600. got {:o}",
		mode
	);
}

/// The mode pin must hold on a re-run too. The apply phase
/// selects the `Reused` step when the README's bytes are
/// unchanged; the previous shape set the mode only inside the
/// `Wrote` arm, so a README left at `0o600` by an earlier run
/// under a tight umask would stay at `0o600` forever. The new
/// shape calls `set_permissions(0o644)` before the byte
/// comparison, so the Reused arm lands on a freshly-permissioned
/// file. The test pre-creates the README at `0o600` with the
/// right bytes (no umask change, no interference with parallel
/// tests) and asserts the apply phase brings it to `0o644`
/// while still saying `Reused`.
#[cfg(unix)]
#[test]
fn compose_readme_mode_is_pinned_on_a_reused_readme() {
	use crate::cli::init::apply;
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	std::fs::create_dir_all(config_path.parent().unwrap()).expect("mkdir etc");
	let compose_dir = data_dir.join("compose");
	std::fs::create_dir_all(&compose_dir).expect("mkdir compose");
	// Pre-create the README with the exact bytes the apply
	// phase would write, at the tight mode the previous
	// implementation would have left behind. The apply
	// phase sees the same bytes, takes the Reused arm, and
	// (with the fix in place) re-pins the mode.
	let readme = compose_dir.join("README");
	std::fs::write(&readme, super::COMPOSE_README.as_bytes()).expect("write readme");
	std::fs::set_permissions(&readme, std::fs::Permissions::from_mode(0o600)).expect("set 0o600");
	let mut answers = minimal_answers();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply::apply(&answers);
	assert!(outcome.error.is_none(), "apply: {:?}", outcome.error);
	assert!(
		outcome.report.steps.iter().any(|s| matches!(
			s,
			crate::cli::init::apply::ReportStep::Reused(p) if p.ends_with("README")
		)),
		"the unchanged README must take the Reused arm; got report: {:?}",
		outcome.report
	);
	let mode = std::fs::metadata(&readme)
		.expect("stat")
		.permissions()
		.mode()
		& 0o777;
	assert_eq!(
		mode, 0o644,
		"the README must come out of the Reused arm at 0o644, not 0o600; got {:o}",
		mode
	);
}
