//! The .deb must depend on `glyndor-archive-keyring` and on `podup`.
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
//! These tests exist so that removing either dependency, which reads as
//! tidying an odd entry, turns something red.

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

#[test]
fn the_binary_package_depends_on_the_archive_keyring() {
	let depends = control_field("Depends");
	assert!(
		depends.iter().any(|dep| dep == "glyndor-archive-keyring"),
		"Depends must name glyndor-archive-keyring so unattended-upgrades covers this package; got: {depends:?}"
	);
}

#[test]
fn the_binary_package_depends_on_podup() {
	let depends = control_field("Depends");
	assert!(
		depends.iter().any(|dep| dep == "podup"),
		"Depends must name podup: epistle cannot run the mail stack without it, and a Recommends is dropped silently where podman is too old; got: {depends:?}"
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
