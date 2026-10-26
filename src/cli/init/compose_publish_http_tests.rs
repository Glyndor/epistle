//! The host address a listener inherits when nothing in the generated file
//! names one: loopback for the three whose transport is HTTP without TLS, the
//! form `init` writes for everything else.

use super::*;

use std::collections::BTreeMap;

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
fn only_a_listener_without_tls_inherits_loopback() {
	let rows = [
		(
			ListenerKind::Api,
			"0.0.0.0",
			Some(8025),
			"127.0.0.1:8025:8025",
		),
		(
			ListenerKind::WebDav,
			"::",
			Some(8090),
			"127.0.0.1:8090:8090",
		),
		(
			ListenerKind::Autoconfig,
			"0.0.0.0",
			Some(8091),
			"127.0.0.1:8091:8091",
		),
		(ListenerKind::Imaps, "::", Some(993), "993:993"),
		(ListenerKind::Smtp, "::", Some(25), "25:25"),
	];
	let listeners = listeners(&rows.map(|(kind, addr, port, _)| (kind, addr, port)));
	assert_eq!(
		published(&listeners, &BTreeMap::new(), None),
		rows.map(|(_, _, _, mapping)| mapping),
	);
	let mut narrow = BTreeMap::new();
	narrow.insert(8090, "203.0.113.5".parse().unwrap());
	assert_eq!(
		published(&listeners, &narrow, None)[1],
		"203.0.113.5:8090:8090",
		"an address the operator chose wins over the default"
	);
	assert!(
		!plain_http(ListenerKind::Imaps) && !plain_http(ListenerKind::Metrics),
		"a TLS listener or a metrics socket is not this rule"
	);
}

/// The three forms the file can name the same wide publication in are one
/// rule: the bare `PORT:PORT` and both wildcards all leave every address of
/// the host, so all of them go to loopback. An address the operator chose for
/// the port is not a wildcard and stays.
#[test]
fn every_wide_publication_of_a_listener_without_tls_narrows_to_loopback() {
	let listeners = listeners(&[(ListenerKind::WebDav, "0.0.0.0", Some(8090))]);
	for wide in ["8090:8090", "0.0.0.0:8090:8090", "[::]:8090:8090"] {
		let document = serde_json::json!({"services": {"mail": {"ports": ["25:25", wide]}}});
		assert_eq!(
			published(&listeners, &hosts(&document), None),
			vec!["127.0.0.1:8090:8090"],
			"{wide} publishes on every address of the host"
		);
	}
	let document =
		serde_json::json!({"services": {"mail": {"ports": ["25:25", "203.0.113.5:8090:8090"]}}});
	assert_eq!(
		published(&listeners, &hosts(&document), None),
		vec!["203.0.113.5:8090:8090"],
		"an address the operator chose for the port is not a wildcard"
	);
}
