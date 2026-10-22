//! The two rules `set` decides on its own, before the loader sees the file:
//! the host-visible socket has to be free, and the API has to earn an address
//! the host can route to.

use super::*;

/// The `[api]` section the loader demands for an api listener, with a token
/// hash in the shape `epistle token-hash` prints.
const API: &str = "[api]\ntoken_hash = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n";
/// A `[tls]` section naming the two files a certificate lives in.
const TLS: &str = "[tls]\ncert_file = \"/cert.pem\"\nkey_file = \"/key.pem\"\n";

/// A configuration with one listener per row, in the order the config lists
/// them, plus the sections `extra` carries.
fn config(extra: &str, rows: &[(ListenerKind, &str, Option<u16>)]) -> Config {
	let mut text = String::from(
		"hostname = \"mail.example.org\"\ndomains = [\"example.org\"]\ndata_dir = \"/var/lib/epistle\"\n",
	);
	for (kind, addr, port) in rows {
		text.push_str(&format!(
			"\n[[listeners]]\nkind = \"{}\"\naddr = \"{addr}\"\n",
			kind.as_str()
		));
		if let Some(port) = port {
			text.push_str(&format!("port = {port}\n"));
		}
	}
	text.push_str(extra);
	toml::from_str(&text).expect("the fixture is what a config loader accepts")
}

/// The message a refusal carries.
fn refusal(result: Result<(), ResourceError>) -> Option<String> {
	result.err().map(|error| error.to_string())
}

#[test]
fn a_port_another_listener_answers_on_is_refused() {
	let two = config(
		"",
		&[
			(ListenerKind::Smtp, "0.0.0.0", None),
			(ListenerKind::Imap, "0.0.0.0", None),
		],
	);
	let narrow = BTreeMap::new();
	for address in ["0.0.0.0", "127.0.0.1"] {
		assert_eq!(
			refusal(free_port(
				&two,
				ListenerKind::Imap,
				&narrow,
				address.parse().unwrap(),
				25,
				false
			)),
			Some("port 25 is already used by smtp on 0.0.0.0:25".to_string()),
			"a wildcard covers every address, so {address} is taken too"
		);
	}
	assert!(
		free_port(
			&two,
			ListenerKind::Imap,
			&narrow,
			"0.0.0.0".parse().unwrap(),
			143,
			false
		)
		.is_ok(),
		"the port the listener already has is its own, not a conflict"
	);
	assert!(
		free_port(
			&two,
			ListenerKind::Imap,
			&narrow,
			"127.0.0.1".parse().unwrap(),
			1143,
			false
		)
		.is_ok(),
		"a port nobody else answers on is free"
	);
}

#[test]
fn in_a_stack_the_published_host_address_is_what_two_mappings_share() {
	// Inside the container both listeners bind every address on 143 and only
	// the host side can tell the mappings apart, so a mapping published on a
	// wildcard takes the specific address too.
	let two = config(
		"",
		&[
			(ListenerKind::Smtp, "0.0.0.0", Some(143)),
			(ListenerKind::Imap, "127.0.0.1", Some(143)),
		],
	);
	assert_eq!(
		refusal(free_port(
			&two,
			ListenerKind::Imap,
			&BTreeMap::new(),
			"127.0.0.1".parse().unwrap(),
			143,
			true
		)),
		Some("port 143 is already used by smtp on 0.0.0.0:143".to_string())
	);
	// The same two listeners on a host install bind the sockets the config
	// says: one loopback port and one wildcard port.
	let host = config(
		"",
		&[
			(ListenerKind::Smtp, "0.0.0.0", Some(143)),
			(ListenerKind::Imap, "127.0.0.1", Some(1143)),
		],
	);
	assert!(
		free_port(
			&host,
			ListenerKind::Imap,
			&BTreeMap::new(),
			"127.0.0.1".parse().unwrap(),
			143,
			true
		)
		.is_err(),
		"with the published map unknown, the wildcard still covers loopback"
	);
	assert!(
		free_port(
			&host,
			ListenerKind::Imap,
			&BTreeMap::new(),
			"127.0.0.1".parse().unwrap(),
			1143,
			false
		)
		.is_ok(),
		"two loopback binds on different ports are two sockets"
	);
}

#[test]
fn http_listener_transport_requires_loopback_in_both_address_families() {
	for kind in [
		ListenerKind::Api,
		ListenerKind::WebDav,
		ListenerKind::Autoconfig,
	] {
		for address in ["127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1"] {
			assert!(http_prerequisites(kind, address.parse().unwrap()).is_ok());
		}
		for address in ["10.0.0.5", "0.0.0.0", "::"] {
			assert!(http_prerequisites(kind, address.parse().unwrap()).is_err());
		}
	}
}

fn fixture(listener: &str) -> (tempfile::TempDir, std::path::PathBuf) {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("mail.toml");
	let text = format!(
		"hostname = 'mail.example.org'\ndomains = ['example.org']\ndata_dir = {:?}\n{TLS}{API}\n[[listeners]]\nkind = '{listener}'\naddr = '127.0.0.1'\n",
		dir.path()
	);
	crate::storage::write_secret(&path, text.as_bytes()).unwrap();
	(dir, path)
}

#[test]
fn invalid_compose_leaves_the_config_unchanged() {
	for bytes in ["{invalid", r#"{"services":{"mail":[]}}"#] {
		let (dir, path) = fixture("imaps");
		let compose = dir.path().join("compose/compose.yaml");
		std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
		std::fs::write(&compose, bytes).unwrap();
		let before = std::fs::read(&path).unwrap();
		let result = run(
			&path,
			Request {
				name: ServiceName::Imaps,
				bind: None,
				port: Some(19994),
			},
			false,
			false,
			&mut Vec::new(),
			&mut Vec::new(),
			|_, _| panic!("failed writes must not reload"),
		);
		assert!(result.is_err());
		assert_eq!(
			std::fs::read(&path).unwrap(),
			before,
			"Compose validation must precede the TOML replacement"
		);
		assert_eq!(std::fs::read_to_string(&compose).unwrap(), bytes);
	}
}

#[test]
fn http_services_refuse_external_binds_even_with_mail_certificates() {
	for (listener, name) in [("api", ServiceName::Api), ("web-dav", ServiceName::Webdav)] {
		for address in ["0.0.0.0", "::", "10.0.0.5", "::ffff:10.0.0.5"] {
			let (_dir, path) = fixture(listener);
			let before = std::fs::read(&path).unwrap();
			let result = run(
				&path,
				Request {
					name,
					bind: Some(address.parse().unwrap()),
					port: None,
				},
				false,
				false,
				&mut Vec::new(),
				&mut Vec::new(),
				|_, _| panic!("refused changes must not reload"),
			);
			assert!(
				matches!(result, Err(ResourceError::Refusal(_))),
				"{listener} on {address}: {result:?}"
			);
			assert_eq!(std::fs::read(&path).unwrap(), before);
		}
	}
}
