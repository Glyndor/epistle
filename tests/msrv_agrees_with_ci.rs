//! Verify the MSRV that CI builds on is the one this crate declares.
//!
//! This asserted `debian/control`'s `Build-Depends: rustc (>= 1.88)` until the
//! .deb moved to a musl build. Debian's toolchain ships no musl standard
//! library, so `Build-Depends` no longer declares a rustc at all, and the
//! counterpart this test compared against stopped existing.
//!
//! Retiring it was the wrong answer. The floor is still a real claim: epistle
//! supports 1.88, and CI proves it by building there. What changed is where the
//! claim lives, so it moved to `rust-version` in `Cargo.toml`, which is where
//! Rust keeps an MSRV and which cargo itself enforces.
//!
//! This is not the derivation standards/testing forbids. That rule is about
//! deriving a **packaging** floor from the manifest, because the real floor
//! comes from transitive dependencies rather than from `edition`. There is no
//! packaging floor now. 1.88 still came from a build that failed, and it still
//! moves the same way.
//!
//! Before #735 the `MSRV` job was gated on an input this repository never
//! passed, so it skipped and its gate read the skip as a pass. A bump that
//! needed a newer compiler would have merged green.

use std::fs;
use std::path::Path;

#[test]
fn ci_msrv_matches_the_declared_rust_version() {
	let root = Path::new(env!("CARGO_MANIFEST_DIR"));

	let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("read ci.yml");
	let msrv = ci
		.lines()
		.find_map(|line| {
			let trimmed = line.trim_start();
			trimmed.strip_prefix("msrv:").map(|rest| {
				let value = match rest.trim().find(" #") {
					Some(idx) => rest.trim()[..idx].trim_end(),
					None => rest.trim(),
				};
				value.trim_matches(['"', '\'']).to_string()
			})
		})
		.expect(
			"no `msrv:` input in .github/workflows/ci.yml. \
			 Without it the MSRV job is skipped and its gate passes vacuously, \
			 which is exactly the state this test exists to prevent.",
		);

	let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read Cargo.toml");
	let floor = manifest
		.lines()
		.find_map(|line| {
			line.trim_start()
				.strip_prefix("rust-version")?
				.split('=')
				.nth(1)
				.map(|value| value.trim().trim_matches(['"', '\'']).to_string())
		})
		.expect(
			"no `rust-version` in Cargo.toml. It is where this crate's MSRV \
			 lives, and without it nothing states the floor CI claims to build on.",
		);

	assert_eq!(
		msrv, floor,
		"the MSRV CI builds on and the floor debian/control promises disagree:\n  \
		 .github/workflows/ci.yml  msrv           = {msrv:?}\n  \
		 debian/control            rustc (>= ...) = {floor:?}\n\
		 Raising the floor means raising both. Find the real floor by building \
		 against it and reading the error, never by reading `rust-version`."
	);
}
