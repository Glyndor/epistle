//! The .deb must depend on `glyndor-archive-keyring` and on
//! `podup` (>= 5.10.10).
//!
//! Automatic updates for Glyndor packages come from one file that package
//! ships, `/etc/apt/apt.conf.d/51glyndor-unattended-upgrades`, which adds the
//! archive to the `unattended-upgrades` allowlist. A box that installed the
//! `.deb` from a GitHub release with `dpkg -i`, or registered the archive by
//! hand, never got that file, and stayed on the version it installed with no
//! signal that anything was wrong (#804). Declaring the keyring in `Depends`
//! makes auto-update a property of the package rather than of the install
//! method: `dpkg -i` refuses until the keyring is present, and the archive
//! resolves it on `apt install`.
//!
//! podup is what runs the mail stack, so a box without it has a binary and no
//! server. It sat in `Recommends` until 0.8.0, and apt drops an unsatisfiable
//! Recommends without a word: on Ubuntu 22.04, where podman is 3.4, `apt
//! install epistle` succeeded and podup was silently left out (#885). In
//! `Depends`, the same install fails and names podman, which is the answer the
//! operator needs.
//!
//! The podup relation carries a floor: features the .deb depends on landed
//! after 5.10.10. Older podups lack them. A `podup` relation without a version
//! is not enough; the floor must be expressed, and the comparison must be
//! numeric per component, not lexicographic, so `5.10.10` rejects `5.9.0`.
//!
//! These tests exist so that removing either dependency, or lowering the
//! podup floor, turns something red.

use std::fs;
use std::path::Path;

fn control_field(field: &str) -> Vec<String> {
	let root = Path::new(env!("CARGO_MANIFEST_DIR"));
	let control = fs::read_to_string(root.join("debian/control")).expect("read debian/control");
	let prefix = format!("{field}:");
	control
		.lines()
		.find_map(|line| line.strip_prefix(prefix.as_str()))
		.map(|value| value.split(',').map(|dep| dep.trim().to_string()).collect())
		.unwrap_or_default()
}

/// Parse one `Depends` entry like `podup (>= 5.10.10)` into the
/// (`package`, `relation`) pair. Returns `None` when the entry is
/// not a relation; returns `Some((pkg, None))` for a bare name
/// like `podup`. Used by the floor assertion so the test names the
/// thing it asserts, and so a future `Depends` change that drops
/// the relation goes red.
fn parse_relation(entry: &str) -> Option<(&str, Option<(&str, &str)>)> {
	let mut parts = entry.splitn(2, ' ');
	let package = parts.next()?.trim();
	let rest = parts.next()?.trim().trim_end_matches(')');
	let (op, version) = rest.split_once(' ')?;
	let op = op.trim_start_matches('(');
	Some((package, Some((op, version))))
}

/// Compare two dotted version strings component by component.
/// Returns `Some(Ordering)` so the helper can be used in assertions;
/// `None` when either side is malformed. The comparison is numeric
/// per component, so `5.10.10 > 5.9.0` and `5.10.10 == 5.10.10` and
/// `6.0 > 5.10.10`. A lexicographic comparison would say
/// `5.9.0 > 5.10.10` and break the floor.
fn version_cmp(a: &str, b: &str) -> Option<std::cmp::Ordering> {
	let parse = |s: &str| -> Option<Vec<u64>> {
		s.split('.').map(|part| part.parse::<u64>().ok()).collect()
	};
	let av = parse(a)?;
	let bv = parse(b)?;
	Some(av.cmp(&bv))
}

#[test]
fn the_binary_package_depends_on_the_archive_keyring() {
	let depends = control_field("Depends");
	assert!(
		depends.iter().any(|dep| dep == "glyndor-archive-keyring"),
		"Depends must name glyndor-archive-keyring so unattended-upgrades covers this package; got: {depends:?}"
	);
}

#[test]
fn the_binary_package_depends_on_podup_with_the_required_floor() {
	let depends = control_field("Depends");
	// Find the entry for podup and parse it as a relation. The test
	// fails with a clear diagnostic when the entry is the bare name
	// (no relation) or when the floor is too low.
	let entry = depends
		.iter()
		.find(|dep| dep.starts_with("podup"))
		.unwrap_or_else(|| panic!("Depends must name podup; got: {depends:?}"));
	let (package, relation) = parse_relation(entry).unwrap_or_else(|| {
		panic!(
			"Depends entry for podup must carry a relation (`podup (>= N)`), \
			 not the bare name; got: {entry:?}"
		)
	});
	assert_eq!(
		package, "podup",
		"the relation's package must be podup; got {package:?}"
	);
	let (op, version) = relation.expect("entry must carry operator and version");
	assert_eq!(op, ">=", "podup relation must be `>=`; got operator {op:?}");
	let actual = version_cmp(version, "5.10.10").unwrap_or_else(|| {
		panic!("podup relation version {version:?} is not a dotted numeric version")
	});
	assert!(
		actual != std::cmp::Ordering::Less,
		"podup floor must be at least 5.10.10; got {version:?}"
	);
}

#[test]
fn the_container_runtime_is_not_merely_recommended() {
	let recommends = control_field("Recommends");
	let demoted: Vec<&String> = recommends
		.iter()
		.filter(|dep| dep.starts_with("podup") || dep.starts_with("podman"))
		.collect();
	assert!(
		demoted.is_empty(),
		"podup and podman belong in Depends, not Recommends; a Recommends is what let epistle install without a runtime; got: {recommends:?}"
	);
}

#[test]
fn version_compare_is_numeric_per_component_not_lexicographic() {
	// Each row pins a comparison the floor depends on. A
	// lexicographic comparison would say `5.9.0 > 5.10.10` because
	// `9 > 1`, and the `5.9.0 < 5.10.10` case goes red. A
	// regression that flips the helper to a string compare shows up
	// here first.
	let rows: &[(&str, &str, std::cmp::Ordering)] = &[
		("5.9.0", "5.10.10", std::cmp::Ordering::Less),
		("5.10.9", "5.10.10", std::cmp::Ordering::Less),
		("5.10.10", "5.10.10", std::cmp::Ordering::Equal),
		("5.11.0", "5.10.10", std::cmp::Ordering::Greater),
		("6.0", "5.10.10", std::cmp::Ordering::Greater),
	];
	for (lhs, rhs, expected) in rows {
		let actual = version_cmp(lhs, rhs)
			.unwrap_or_else(|| panic!("version_cmp({lhs:?}, {rhs:?}) returned None"));
		assert_eq!(
			actual, *expected,
			"version_cmp({lhs:?}, {rhs:?}) must be {expected:?}"
		);
	}
}
