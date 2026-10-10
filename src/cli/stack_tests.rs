//! Unit tests for the version floor and the table formatter.
//!
//! The integration coverage in `tests/stack_podup.rs` drives the real
//! binary against a stub `podup` on `PATH`; this file stays inside
//! the module so the helpers (`version_at_least`, `parse_version`,
//! the table) and the `debian/control` constant-pin test run in
//! the same compile unit.

use super::{PODUP_FLOOR, format_ports, parse_version, version_at_least};
use crate::config::Config;

#[test]
fn parse_version_returns_one_number_per_dotted_component() {
	let parsed = parse_version("5.10.10").expect("parses");
	assert_eq!(parsed, vec![5, 10, 10]);
}

#[test]
fn version_at_least_is_numeric_per_component_not_lexicographic() {
	// Each row pins a comparison the floor depends on. A
	// lexicographic comparison would say `5.9.0 >= 5.10.10` because
	// `9 > 1`, and the `5.9.0` row goes red. A regression that
	// flips the helper to a string compare shows up here first.
	let rows: &[(&str, bool)] = &[
		("5.9.0", false),
		("5.10.9", false),
		("5.10.10", false),
		("5.10.13", true),
		("5.11.0", true),
		("6.0", true),
	];
	for (input, expected) in rows {
		let actual = version_at_least(input, PODUP_FLOOR);
		assert_eq!(
			actual, *expected,
			"version_at_least({input:?}, {PODUP_FLOOR:?}) must be {expected}"
		);
	}
}

#[test]
fn floor_constant_matches_debian_control() {
	// The `podup (>= X.Y.Z)` line is what apt reads at install time;
	// the same X.Y.Z is the floor this binary enforces at run time.
	// If the two ever drift, the operator gets one answer from apt
	// and another from `epistle stack`; the test pins them together.
	let control = std::fs::read_to_string("debian/control").expect("read debian/control");
	let floor = control
		.lines()
		.find_map(|line| {
			let trimmed = line.trim_start();
			let after = trimmed.strip_prefix("Depends:")?;
			after
				.split(',')
				.find_map(|dep| dep.trim().strip_prefix("podup (>= "))
				.map(|version| version.trim_end_matches(')').to_string())
		})
		.unwrap_or_else(|| panic!("debian/control must declare `podup (>= X.Y.Z)`"));
	assert_eq!(
		floor, PODUP_FLOOR,
		"debian/control declares podup >= {floor}, but the runtime floor is {PODUP_FLOOR}; the two must agree"
	);
}

#[test]
fn config_load_succeeds_with_a_minimal_stack_relevant_config() {
	// A stack command only needs `data_dir`; the loader must accept
	// a config that has nothing else. Kept here so a future config
	// refactor that hardens the schema can be aimed at the same
	// contract.
	let dir = tempfile::tempdir().expect("tempdir");
	let body = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\n",
		dir.path()
	);
	let path = dir.path().join("mail.toml");
	std::fs::write(&path, body).expect("write config");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
			.expect("restrict config");
	}
	let config = Config::load(&path).expect("config loads");
	assert_eq!(config.data_dir, dir.path());
}

#[test]
fn format_ports_renders_a_dash_for_no_publishers() {
	// An empty list is the common case for a service that listens
	// on the podman network only. The table must not show a blank
	// cell; `-` matches the health column's fallback.
	assert_eq!(format_ports(&[]), "-");
}

#[test]
fn ps_parser_accepts_published_port_null_for_unpublished_mappings() {
	// podup 5.10.10 emits `PublishedPort: null` for a container
	// that exposes a port without publishing it on a host
	// interface. The old `u16` field rejected the entire service
	// array; the row below would not parse before this commit, so
	// `ps` and `ps --json` both exited 1 on a service whose
	// container port 5432 has no host binding. The test only
	// asserts that the decode succeeds; the broken field makes
	// `serde_json::from_str` return `Err`, which the match turns
	// into a panic so the suite goes red.
	let json = r#"{
	    "URL": "",
	    "TargetPort": 5432,
	    "PublishedPort": null,
	    "Protocol": "tcp"
	  }"#;
	let _publisher: super::Publisher = match serde_json::from_str(json) {
		Ok(p) => p,
		Err(error) => panic!(
			"a null PublishedPort must decode cleanly; the broken `u16` field rejected it: {error}"
		),
	};
}

#[test]
fn format_ports_renders_an_unpublished_target_without_a_host_binding() {
	// The null `PublishedPort` case (see `ps_parser_accepts_*`)
	// reaches the table formatter too: a port that has no host
	// binding renders as `target/proto` (no `host:published->`
	// prefix), so the cell keeps the same shape it has for a
	// published port while making the missing binding obvious.
	let json = r#"{
	  "URL": "",
	  "TargetPort": 5432,
	  "PublishedPort": null,
	  "Protocol": "tcp"
	}"#;
	let publisher: super::Publisher = match serde_json::from_str(json) {
		Ok(p) => p,
		Err(error) => {
			panic!("null PublishedPort must decode; the broken `u16` field rejected it: {error}")
		}
	};
	assert_eq!(format_ports(std::slice::from_ref(&publisher)), "5432/tcp");
}
