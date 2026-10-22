//! The host side of the generated port map: how a mapping renders, how it is
//! read back, and how the operator's override is recognised.

use super::*;

use std::net::Ipv4Addr;

/// A compose document whose `mail` service publishes `mappings`.
fn compose(mappings: &[&str]) -> serde_json::Value {
	serde_json::json!({
		"services": {"mail": {"image": "keep", "ports": mappings}}
	})
}

/// Listeners with one per `(kind, addr, port)` triple.
fn listeners(rows: &[(ListenerKind, &str, Option<u16>)]) -> Vec<Listener> {
	rows.iter()
		.map(|(kind, addr, port)| Listener {
			kind: *kind,
			addr: addr.parse().expect("address"),
			port: *port,
		})
		.collect()
}

#[test]
fn a_mapping_renders_and_reads_back_the_host_address_it_fixes() {
	for (mapping, host, port) in [
		("143:143", None, 143),
		(
			"127.0.0.1:143:143",
			Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
			143,
		),
		(
			"10.0.0.5:8025:8025",
			Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
			8025,
		),
		(
			"[::1]:143:143",
			Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
			143,
		),
	] {
		assert_eq!(entry(host, port), mapping);
		assert_eq!(parse(mapping), Some((host, port)));
	}
	assert_eq!(
		entry(None, 25),
		"25:25",
		"an unspecified host address keeps the form init writes"
	);
	assert_eq!(
		entry(Some(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)), 25),
		"0.0.0.0:25:25",
		"an explicit wildcard preserves the requested address family"
	);
}

#[test]
fn something_that_is_not_a_mapping_of_ours_is_not_a_mapping() {
	for mapping in ["143", "", "143:144", "hostname:143:143", "143:143/udp"] {
		assert_eq!(parse(mapping), None, "{mapping:?} is not a mapping");
	}
}

#[test]
fn a_second_change_keeps_the_host_address_the_first_one_fixed() {
	// IMAP was narrowed to loopback, then another service was enabled. The
	// renderer has to carry the narrow address over or the second change puts
	// IMAP back on every host address of the machine.
	let narrow = hosts(&compose(&["25:25", "127.0.0.1:143:143", "8090:8090"]));
	assert_eq!(
		narrow.get(&143).map(IpAddr::to_string),
		Some("127.0.0.1".to_string())
	);
	assert_eq!(
		narrow.len(),
		1,
		"only a mapping that names an address counts"
	);
	assert_eq!(
		published(
			&listeners(&[
				(ListenerKind::Smtp, "::", None),
				(ListenerKind::Imap, "0.0.0.0", None),
				(ListenerKind::WebDav, "0.0.0.0", None),
			]),
			&narrow,
			None,
		),
		["25:25", "127.0.0.1:143:143", "8090:8090"],
		"a mapping nobody narrowed keeps the form init writes"
	);
}

#[test]
fn the_override_is_recognised_only_inside_the_mail_service() {
	let dir = tempfile::tempdir().unwrap();
	let compose_dir = dir.path().join("compose");
	std::fs::create_dir_all(&compose_dir).unwrap();
	for (override_text, ports, expected) in [
		(
			"services:\n  mail:\n    ports: !override\n      - \"25:25\"\n      - \"143:143\"\n",
			[143],
			true,
		),
		(
			"services:\n  mail:\n    ports:\n      - \"127.0.0.1:8025:8025\"\n",
			[8025],
			true,
		),
		(
			"services:\n  mail:\n    ports: [\"25:25\", \"143:143\"]\n",
			[143],
			true,
		),
		(
			"services:\n  mail:\n    mem_limit: 143m\n  db:\n    ports:\n      - \"5432:5432\"\n",
			[143],
			false,
		),
		(
			"services:\n  mail:\n    ports: !override\n      - \"25:25\"\n    cpus: 2\n",
			[143],
			false,
		),
		("", [143], false),
	] {
		let path = compose_dir.join("compose.override.yaml");
		std::fs::write(&path, override_text).unwrap();
		assert_eq!(
			override_publishes(dir.path(), &ports),
			expected,
			"override {override_text:?} over port {ports:?}"
		);
	}
	assert!(
		!override_publishes(&dir.path().join("elsewhere"), &[143]),
		"a stack with no override file names no port"
	);
}

#[test]
fn the_map_is_rewritten_only_when_it_moves() {
	let dir = tempfile::tempdir().unwrap();
	let path = super::super::compose::compose_file_path(dir.path());
	std::fs::create_dir_all(path.parent().unwrap()).unwrap();
	std::fs::write(&path, serde_json::to_vec(&compose(&["25:25"])).unwrap()).unwrap();
	let rows = listeners(&[
		(ListenerKind::Smtp, "::", None),
		(ListenerKind::Imap, "0.0.0.0", None),
	]);
	let narrow = Some((ListenerKind::Imap, Some(IpAddr::V4(Ipv4Addr::LOCALHOST))));
	assert_eq!(
		update(dir.path(), &rows, narrow).expect("a readable generated file"),
		Some(true)
	);
	let written: serde_json::Value =
		serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
	assert_eq!(
		written["services"]["mail"]["ports"],
		serde_json::json!(["25:25", "127.0.0.1:143:143"])
	);
	assert_eq!(
		written["services"]["mail"]["image"], "keep",
		"the map is the only key this touches"
	);
	let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
	assert_eq!(
		update(dir.path(), &rows, narrow).expect("a readable generated file"),
		Some(false),
		"the same request must not rewrite the file"
	);
	assert_eq!(
		std::fs::metadata(&path).unwrap().modified().unwrap(),
		modified
	);

	// Moving the listener takes its host address with it: `set` names the
	// address it recovered for the port the listener had.
	let moved = listeners(&[
		(ListenerKind::Smtp, "::", None),
		(ListenerKind::Imap, "0.0.0.0", Some(1143)),
	]);
	assert_eq!(
		update(dir.path(), &moved, narrow).expect("a readable generated file"),
		Some(true)
	);
	let written: serde_json::Value =
		serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
	assert_eq!(
		written["services"]["mail"]["ports"],
		serde_json::json!(["25:25", "127.0.0.1:1143:1143"])
	);
	assert_eq!(
		update(&dir.path().join("absent"), &rows, None).expect("an absent stack is not an error"),
		None,
		"a host install has no map to write"
	);
}

#[test]
fn a_loopback_listener_stays_out_of_the_map() {
	let rows = listeners(&[
		(ListenerKind::Api, "127.0.0.1", None),
		(ListenerKind::Smtp, "::", None),
	]);
	assert_eq!(published(&rows, &BTreeMap::new(), None), ["25:25"]);
	// Even pinned to a host address, a loopback bind answers nothing through
	// the pasta mapping, so the mapping would publish a port that refuses.
	assert_eq!(
		published(
			&rows,
			&BTreeMap::new(),
			Some((ListenerKind::Api, Some("127.0.0.1".parse().unwrap())))
		),
		["25:25"]
	);
	assert_eq!(
		published(
			&listeners(&[(ListenerKind::Api, "0.0.0.0", None)]),
			&BTreeMap::new(),
			Some((ListenerKind::Api, Some("10.0.0.5".parse().unwrap())))
		),
		["10.0.0.5:8025:8025"],
		"a listener the container binds on every address is published on the host one"
	);
}

#[test]
fn an_unreadable_or_foreign_file_names_no_host_address() {
	let dir = tempfile::tempdir().unwrap();
	let path = super::super::compose::compose_file_path(dir.path());
	std::fs::create_dir_all(path.parent().unwrap()).unwrap();
	assert!(
		hosts_in_file(&path).is_empty(),
		"no compose file at all: a host install"
	);
	std::fs::write(&path, b"not the JSON epistle init writes").unwrap();
	assert!(hosts_in_file(&path).is_empty());
	std::fs::write(
		&path,
		serde_json::to_vec(&serde_json::json!({"services": {"db": {}}})).unwrap(),
	)
	.unwrap();
	assert!(
		hosts_in_file(&path).is_empty(),
		"a file with no mail service pins nothing"
	);
}

#[test]
fn explicit_wildcards_keep_the_requested_address_family() {
	for (address, mapping) in [("0.0.0.0", "0.0.0.0:993:993"), ("::", "[::]:993:993")] {
		let address = address.parse().unwrap();
		let rows = listeners(&[(ListenerKind::Imaps, "0.0.0.0", None)]);
		let rendered = published(
			&rows,
			&BTreeMap::new(),
			Some((ListenerKind::Imaps, Some(address))),
		);
		assert_eq!(rendered, [mapping]);
		let recovered = hosts(&compose(&[mapping]));
		assert_eq!(published(&rows, &recovered, None), [mapping]);
	}
}

#[test]
fn single_inline_override_ports_are_reported_without_writing_the_override() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("compose/compose.override.yaml");
	std::fs::create_dir_all(path.parent().unwrap()).unwrap();
	for value in [
		r#"["19993:19993"]"#,
		r#"!override ["19993:19993"]"#,
		r#"[{target: 19993, published: "19993", protocol: tcp}]"#,
	] {
		let text = format!("services:\n  mail:\n    ports: {value}\n");
		std::fs::write(&path, &text).unwrap();
		assert!(override_publishes(dir.path(), &[19993]), "{value}");
		assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
	}
}
