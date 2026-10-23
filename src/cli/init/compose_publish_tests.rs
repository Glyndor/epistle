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
	// pasta on Podman 5.4.2 refuses an explicit wildcard, and a wildcard
	// publishes on every address of the host either way, so the family it
	// names is kept in the container bind instead of in the mapping.
	for wildcard in ["0.0.0.0", "::"] {
		assert_eq!(entry(Some(wildcard.parse().unwrap()), 25), "25:25");
		assert_eq!(
			parse(&format!("{wildcard}:25:25")),
			Some((Some(wildcard.parse().unwrap()), 25)),
			"an older file with the explicit form still reads back its address"
		);
	}
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
	// IMAP back on every host address of the machine. WebDAV, which the map
	// says nothing about, stays on loopback because its transport is HTTP
	// without TLS.
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
		["25:25", "127.0.0.1:143:143", "127.0.0.1:8090:8090"],
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
fn the_map_is_staged_only_when_it_moves() {
	let dir = tempfile::tempdir().unwrap();
	let path = super::super::compose::compose_file_path(dir.path());
	std::fs::create_dir_all(path.parent().unwrap()).unwrap();
	let original = br#"{"services":{"mail":{"image":"keep","ports":["25:25"]}}}"#;
	std::fs::write(&path, original).unwrap();
	let rows = listeners(&[
		(ListenerKind::Smtp, "::", None),
		(ListenerKind::Imap, "0.0.0.0", None),
	]);
	let narrow = Some((ListenerKind::Imap, Some(IpAddr::V4(Ipv4Addr::LOCALHOST))));
	let staged = prepare(dir.path(), &rows, narrow).expect("a readable generated file");
	let candidate = staged
		.companion
		.as_ref()
		.expect("the map moves")
		.candidate
		.clone();
	let written: serde_json::Value = serde_json::from_slice(&candidate).unwrap();
	assert_eq!(
		written["services"]["mail"]["ports"],
		serde_json::json!(["25:25", "127.0.0.1:143:143"])
	);
	assert_eq!(
		written["services"]["mail"]["image"], "keep",
		"the map is the only key this touches"
	);
	assert_eq!(
		std::fs::read(&path).unwrap(),
		original,
		"staging a candidate must not write the file"
	);
	std::fs::write(&path, &candidate).unwrap();
	assert!(
		prepare(dir.path(), &rows, narrow)
			.expect("a readable generated file")
			.companion
			.is_none(),
		"a map that does not move must not be staged again"
	);

	// Moving the listener takes its host address with it: `set` names the
	// address it recovered for the port the listener had.
	let moved = listeners(&[
		(ListenerKind::Smtp, "::", None),
		(ListenerKind::Imap, "0.0.0.0", Some(1143)),
	]);
	let staged = prepare(dir.path(), &moved, narrow).expect("a readable generated file");
	let written: serde_json::Value =
		serde_json::from_slice(&staged.companion.expect("the map moves").candidate).unwrap();
	assert_eq!(
		written["services"]["mail"]["ports"],
		serde_json::json!(["25:25", "127.0.0.1:1143:1143"])
	);
	assert!(
		prepare(&dir.path().join("absent"), &rows, None)
			.expect("an absent stack is not an error")
			.companion
			.is_none(),
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
		hosts_in_file(&path).unwrap().is_empty(),
		"no compose file at all: a host install"
	);
	std::fs::write(&path, b"not the JSON epistle init writes").unwrap();
	assert!(hosts_in_file(&path).unwrap().is_empty());
	std::fs::write(
		&path,
		serde_json::to_vec(&serde_json::json!({"services": {"db": {}}})).unwrap(),
	)
	.unwrap();
	assert!(
		hosts_in_file(&path).unwrap().is_empty(),
		"a file with no mail service pins nothing"
	);
}

#[test]
fn an_explicit_wildcard_renders_as_the_form_the_engine_accepts() {
	// The family the operator asked for lives in the bind the container
	// uses (`service set`), so the mapping itself is the plain form for a
	// wildcard, and reading the map back keeps it there on every rewrite.
	for address in ["0.0.0.0", "::"] {
		let address = address.parse().unwrap();
		let rows = listeners(&[(ListenerKind::Imaps, "::", None)]);
		let rendered = published(
			&rows,
			&BTreeMap::new(),
			Some((ListenerKind::Imaps, Some(address))),
		);
		assert_eq!(rendered, ["993:993"]);
		let recovered = hosts(&compose(&["993:993"]));
		assert_eq!(published(&rows, &recovered, None), ["993:993"]);
	}
}

#[test]
fn an_override_written_in_flow_style_or_with_ranges_is_still_reported() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("compose/compose.override.yaml");
	std::fs::create_dir_all(path.parent().unwrap()).unwrap();
	for (text, expected) in [
		(
			"services:\n  mail: {image: keep, ports: [\"25:25\", \"143:143\"]}\n",
			true,
		),
		(
			"services:\n  mail: {image: keep, ports: [\"25:25\"]}\n",
			false,
		),
		(
			"services:\n  \"mail\":\n    ports:\n      - \"143:143\"\n",
			true,
		),
		(
			"services:\n  mail:\n    ports:\n      - \"990-999:990-999\"\n",
			true,
		),
		(
			"services:\n  mail:\n    ports:\n      - \"900-902:900-902\"\n",
			false,
		),
		(
			"services:\n  mail:\n    ports:\n      - \"990-995:990-995\"\n",
			true,
		),
	] {
		std::fs::write(&path, text).unwrap();
		assert_eq!(
			override_publishes(dir.path(), &[993, 143]),
			expected,
			"{text:?}"
		);
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
