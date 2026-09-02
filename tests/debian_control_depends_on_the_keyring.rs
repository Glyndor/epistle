//! The .deb must depend on `glyndor-archive-keyring`.
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
//! This test exists so that removing the dependency, which reads as tidying
//! an odd entry, turns something red.

use std::fs;
use std::path::Path;

#[test]
fn the_binary_package_depends_on_the_archive_keyring() {
	let root = Path::new(env!("CARGO_MANIFEST_DIR"));
	let control = fs::read_to_string(root.join("debian/control")).expect("read debian/control");

	let depends = control
		.lines()
		.find_map(|line| line.strip_prefix("Depends:"))
		.expect("debian/control declares a Depends line for the binary package");

	let names: Vec<&str> = depends.split(',').map(|dep| dep.trim()).collect();
	assert!(
		names.contains(&"glyndor-archive-keyring"),
		"Depends must name glyndor-archive-keyring so unattended-upgrades covers this package; got: {depends}"
	);
}
