//! Verify the MSRV that CI builds on is the floor `debian/control` promises.
//!
//! `Build-Depends` carries `rustc (>= 1.88)`. That is a promise to whoever
//! installs the `.deb` on a distribution shipping exactly that compiler, and
//! it is only worth anything if something builds on it. Until `ci.yml` gained
//! an `msrv` input, nothing did: CI pinned 1.98, the `MSRV` job was gated on
//! `inputs.msrv != ''` and never ran, and its aggregate gate treated the skip
//! as a pass — a green check that had looked at nothing.
//!
//! The floor itself is deliberately *not* derived from `rust-version` or
//! `edition`; standards/testing forbids that, because the real floor comes
//! from transitive dependencies rather than the manifest. This test does not
//! decide what the floor should be. It asserts that the two places already
//! declaring one agree, so raising it in the packaging without raising it in
//! CI (or the reverse) fails here instead of on a user's machine.

use std::fs;
use std::path::Path;

#[test]
fn ci_msrv_matches_the_debian_rustc_floor() {
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

	let control = fs::read_to_string(root.join("debian/control")).expect("read debian/control");
	let floor = control
		.lines()
		.find(|line| line.starts_with("Build-Depends:"))
		.and_then(|line| {
			let start = line.find("rustc (>=")? + "rustc (>=".len();
			let rest = &line[start..];
			let end = rest.find(')')?;
			Some(rest[..end].trim().to_string())
		})
		.expect("no `rustc (>= x.y)` in the Build-Depends line of debian/control");

	assert_eq!(
		msrv, floor,
		"the MSRV CI builds on and the floor debian/control promises disagree:\n  \
		 .github/workflows/ci.yml  msrv           = {msrv:?}\n  \
		 debian/control            rustc (>= ...) = {floor:?}\n\
		 Raising the floor means raising both. Find the real floor by building \
		 against it and reading the error, never by reading `rust-version`."
	);
}
