//! The panel's port: the mail container owns the namespace the panel joins, so
//! the mail service's `ports:` array carries it, on the host's loopback.

use super::*;

use std::collections::BTreeMap;

fn smtp() -> Vec<Listener> {
	vec![Listener {
		kind: ListenerKind::Smtp,
		addr: "::".parse().expect("address"),
		port: None,
	}]
}

#[test]
fn the_panel_port_goes_on_loopback_and_only_when_the_stack_runs_the_panel() {
	assert_eq!(
		published(&smtp(), &BTreeMap::new(), None, None, Some(7587)),
		["25:25", "127.0.0.1:7587:7587"],
		"the panel serves plain HTTP: TLS is the operator's proxy"
	);
	assert_eq!(
		published(&smtp(), &BTreeMap::new(), None, None, None),
		["25:25"]
	);
}

#[test]
fn the_address_the_operator_gave_the_panel_port_survives_a_re_render() {
	let document = serde_json::json!({
		"services": {"mail": {"ports": ["25:25", "10.0.0.5:7587:7587"]}}
	});
	assert_eq!(
		published(&smtp(), &hosts(&document), None, None, Some(7587)),
		["25:25", "10.0.0.5:7587:7587"]
	);
}

#[test]
fn a_wide_publication_of_the_panel_port_narrows_to_loopback() {
	for wide in ["7587:7587", "0.0.0.0:7587:7587", "[::]:7587:7587"] {
		let document = serde_json::json!({"services": {"mail": {"ports": ["25:25", wide]}}});
		assert_eq!(
			published(&smtp(), &hosts(&document), None, None, Some(7587)),
			["25:25", "127.0.0.1:7587:7587"],
			"{wide} would serve the panel's plain HTTP on every address of the host"
		);
	}
}

/// A compose file whose `mail` publishes `mappings`, with a `panel` service
/// when `panel` is set, staged the way `epistle service set` stages it.
fn staged_ports(panel: bool, mappings: &[&str]) -> Option<serde_json::Value> {
	let dir = tempfile::tempdir().unwrap();
	let path = super::super::super::compose::compose_file_path(dir.path());
	std::fs::create_dir_all(path.parent().unwrap()).unwrap();
	let mut services = serde_json::json!({"mail": {"image": "keep", "ports": mappings}});
	if panel {
		services["panel"] = serde_json::json!({"image": "ghcr.io/glyndor/epistle-panel:0.3.1"});
	}
	std::fs::write(&path, serde_json::json!({"services": services}).to_string()).unwrap();
	let staged = prepare(dir.path(), &smtp(), None, None).expect("a readable generated file");
	staged.companion.map(|companion| {
		let written: serde_json::Value = serde_json::from_slice(&companion.candidate).unwrap();
		written["services"]["mail"]["ports"].clone()
	})
}

#[test]
fn rewriting_the_map_keeps_the_panel_port_of_a_file_that_runs_the_panel() {
	assert_eq!(
		staged_ports(true, &["25:25", "10.0.0.5:7587:7587"]),
		None,
		"a map that already carries the panel does not move"
	);
	assert_eq!(
		staged_ports(true, &["25:25", "143:143", "127.0.0.1:7587:7587"]),
		Some(serde_json::json!(["25:25", "127.0.0.1:7587:7587"])),
		"dropping another listener must not take the panel's port away"
	);
}

#[test]
fn a_file_without_the_panel_gets_no_panel_port() {
	assert_eq!(
		staged_ports(false, &["25:25", "143:143"]),
		Some(serde_json::json!(["25:25"]))
	);
}
