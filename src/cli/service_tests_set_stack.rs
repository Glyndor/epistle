//! The rules `set` decides on a container stack: the bind the container
//! answers on, the address the host reaches it on, the port it can take, and
//! what the command says about it.

use super::*;

/// A stack: the same configuration with one listener on `addr`, and the
/// generated Compose file beside it with `ports` as its map.
fn stack(
	listeners: &[(&str, &str, u16)],
	ports: &[&str],
) -> (tempfile::TempDir, std::path::PathBuf) {
	let (dir, path) = fixture("smtp");
	let mut text = std::fs::read_to_string(&path).unwrap();
	for (kind, addr, port) in listeners {
		text.push_str(&format!(
			"[[listeners]]\nkind = '{kind}'\naddr = '{addr}'\nport = {port}\n"
		));
	}
	crate::storage::write_secret(&path, text.as_bytes()).unwrap();
	let compose = dir.path().join("compose/compose.yaml");
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(
		&compose,
		serde_json::to_vec(&serde_json::json!({"services": {"mail": {"ports": ports}}})).unwrap(),
	)
	.unwrap();
	(dir, path)
}

/// The `ports:` map of the generated file of a stack fixture.
fn ports_of(dir: &std::path::Path) -> Vec<String> {
	let compose = dir.join("compose/compose.yaml");
	let document: serde_json::Value =
		serde_json::from_slice(&std::fs::read(compose).unwrap()).unwrap();
	document["services"]["mail"]["ports"]
		.as_array()
		.unwrap()
		.iter()
		.map(|value| value.as_str().unwrap().to_string())
		.collect()
}

/// The address of one listener in the configuration a command left behind.
fn addr_of(path: &std::path::Path, kind: &str) -> String {
	Config::load(path)
		.unwrap()
		.listeners
		.into_iter()
		.find(|listener| listener.kind.as_str() == kind)
		.unwrap()
		.addr
		.to_string()
}

/// Move `name` to the address the operator named, reporting to `out` and
/// `status`, and refusing to restart anything.
fn set_to(
	path: &std::path::Path,
	name: ServiceName,
	bind: Option<&str>,
	port: Option<u16>,
	json: bool,
	out: &mut Vec<u8>,
	status: &mut Vec<u8>,
) -> Result<std::process::ExitCode, ResourceError> {
	run(
		path,
		Request {
			name,
			bind: bind.map(|address| address.parse().unwrap()),
			port,
		},
		false,
		json,
		out,
		status,
		|_, _| std::process::ExitCode::SUCCESS,
	)
}

/// The container side of a mapping follows the family the operator asked for:
/// a container that binds `0.0.0.0` answers nothing on an IPv6 host address,
/// which is the family `init` publishes on by default.
#[test]
fn the_container_bind_keeps_the_family_the_operator_asked_for() {
	for (current, requested, written) in [
		// Already dual-stack: the requested family is answered either way.
		("::", "::1", None),
		("::", "0.0.0.0", None),
		("::", "10.0.0.5", None),
		// IPv4 only, asked for IPv6: the dual-stack bind is the only one that
		// answers the requested address.
		("0.0.0.0", "::1", Some("::")),
		("0.0.0.0", "2001:db8::1", Some("::")),
		// IPv6 only, asked for IPv4: `::` is dual-stack, so it stays.
		("::1", "127.0.0.1", Some("0.0.0.0")),
		// A loopback or private bind inside the container is not one the
		// mapping reaches.
		("127.0.0.1", "0.0.0.0", Some("0.0.0.0")),
		("10.0.0.5", "127.0.0.1", Some("0.0.0.0")),
		("10.0.0.5", "10.0.0.6", Some("0.0.0.0")),
	] {
		let requested = requested.parse().unwrap();
		assert_eq!(
			container_bind(current.parse().unwrap(), requested),
			written.map(|address| address.parse().unwrap()),
			"from {current} to {requested}"
		);
	}
}

#[test]
fn a_published_ipv6_address_keeps_a_dual_stack_container_bind() {
	for (addr, mapping) in [("::", "[::1]:993:993"), ("0.0.0.0", "[::1]:993:993")] {
		let (dir, path) = stack(&[("imaps", addr, 993)], &["993:993"]);
		set_to(
			&path,
			ServiceName::Imaps,
			Some("::1"),
			None,
			false,
			&mut Vec::new(),
			&mut Vec::new(),
		)
		.unwrap();
		assert_eq!(
			addr_of(&path, "imaps"),
			"::",
			"a container bound on {addr} can not answer an IPv6 mapping"
		);
		assert_eq!(ports_of(dir.path()), [mapping]);
	}
}

#[test]
fn a_wildcard_publishes_every_address_and_says_so() {
	let (dir, path) = stack(&[("imaps", "::", 993)], &["993:993"]);
	let (mut out, mut status) = (Vec::new(), Vec::new());
	set_to(
		&path,
		ServiceName::Imaps,
		Some("0.0.0.0"),
		Some(1465),
		false,
		&mut out,
		&mut status,
	)
	.unwrap();
	assert_eq!(
		String::from_utf8(status).unwrap(),
		"imaps published on every address on port 1465.\n"
	);
	assert_eq!(addr_of(&path, "imaps"), "::");
	assert_eq!(ports_of(dir.path()), ["1465:1465"]);
}

#[test]
fn a_listener_the_container_holds_on_loopback_is_reported_as_set_not_published() {
	let (dir, path) = stack(&[("api", "127.0.0.1", 8025)], &[]);
	let (mut out, mut status) = (Vec::new(), Vec::new());
	set_to(
		&path,
		ServiceName::Api,
		None,
		Some(8026),
		false,
		&mut out,
		&mut status,
	)
	.unwrap();
	assert_eq!(
		String::from_utf8(status).unwrap(),
		"api set to 127.0.0.1:8026.\n",
		"a loopback listener inside the container publishes nothing"
	);
	assert!(
		ports_of(dir.path()).is_empty(),
		"the map can not name an address the container does not bind"
	);
	assert_eq!(addr_of(&path, "api"), "127.0.0.1");
}

#[test]
fn a_dry_run_in_json_carries_the_compose_change_it_would_make() {
	let (dir, path) = stack(&[("imaps", "::", 993)], &["993:993"]);
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let code = run(
		&path,
		Request {
			name: ServiceName::Imaps,
			bind: Some("127.0.0.1".parse().unwrap()),
			port: None,
		},
		true,
		true,
		&mut out,
		&mut status,
		|_, _| panic!("a dry run must not restart"),
	)
	.unwrap();
	assert_eq!(code, std::process::ExitCode::SUCCESS);
	let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
	assert_eq!(
		value["ports"],
		serde_json::json!({"current": ["993:993"], "wanted": ["127.0.0.1:993:993"]}),
		"a consumer of the JSON has to see the map move: {value}"
	);
	assert_eq!(
		ports_of(dir.path()),
		["993:993"],
		"a dry run writes nothing"
	);
}

#[test]
fn an_address_no_interface_of_the_host_owns_is_refused_before_anything_is_written() {
	for address in ["224.0.0.1", "ff02::1", "255.255.255.255", "fe80::1"] {
		assert!(host_address(address.parse().unwrap()).is_err(), "{address}");
	}
	// A mapped form is the address it names, not a second one.
	assert_eq!(
		host_address("::ffff:10.0.0.5".parse().unwrap())
			.unwrap()
			.to_string(),
		"10.0.0.5"
	);
	for address in ["0.0.0.0", "::", "10.0.0.5", "2001:db8::1", "127.0.0.1"] {
		assert!(host_address(address.parse().unwrap()).is_ok(), "{address}");
	}
	let (dir, path) = stack(&[("imaps", "::", 993)], &["993:993"]);
	let before = std::fs::read(&path).unwrap();
	let error = set_to(
		&path,
		ServiceName::Imaps,
		Some("224.0.0.1"),
		None,
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	)
	.unwrap_err();
	assert!(matches!(error, ResourceError::Refusal(_)), "{error}");
	assert_eq!(std::fs::read(&path).unwrap(), before);
	assert_eq!(ports_of(dir.path()), ["993:993"]);
}

/// The override is merged with the generated map, or replaces it where it
/// carries `!override`: saying it wins would contradict what the engine does
/// with a plain list. It is said whether or not this change moved anything,
/// because it is the override that answers, not the change.
#[test]
fn a_published_listener_with_an_override_says_how_the_two_combine() {
	let (dir, path) = stack(&[("imaps", "::", 993)], &["993:993"]);
	let override_path = dir.path().join("compose/compose.override.yaml");
	std::fs::write(
		&override_path,
		"services:\n  mail:\n    ports: [\"993:993\"]\n",
	)
	.unwrap();
	let before = std::fs::read_to_string(&override_path).unwrap();
	let (mut out, mut status) = (Vec::new(), Vec::new());
	set_to(
		&path,
		ServiceName::Imaps,
		Some("127.0.0.1"),
		None,
		false,
		&mut out,
		&mut status,
	)
	.unwrap();
	assert_eq!(
		String::from_utf8(status).unwrap(),
		"imaps published on 127.0.0.1:993.\ncompose.override.yaml publishes a port for mail: it merges with the generated map, or replaces it where it carries !override.\n"
	);
	assert_eq!(
		std::fs::read_to_string(&override_path).unwrap(),
		before,
		"the operator override is never written"
	);
	assert_eq!(ports_of(dir.path()), ["127.0.0.1:993:993"]);

	// Asking for what the map already pins changes nothing, and the override
	// still answers for the port.
	let (mut out, mut status) = (Vec::new(), Vec::new());
	set_to(
		&path,
		ServiceName::Imaps,
		Some("127.0.0.1"),
		None,
		false,
		&mut out,
		&mut status,
	)
	.unwrap();
	assert_eq!(
		String::from_utf8(status).unwrap(),
		"imaps is already published on 127.0.0.1:993; nothing changed.\ncompose.override.yaml publishes a port for mail: it merges with the generated map, or replaces it where it carries !override.\n"
	);
	assert_eq!(ports_of(dir.path()), ["127.0.0.1:993:993"]);
}
