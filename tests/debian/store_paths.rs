//! Cross-file contract tests for the package maintainer script and the Rust
//! rollback store. A regression on either side breaks the published pair the
//! operator reaches through `stack rollback`, and the only place where both
//! names live together is here.
//!
//! The tests read `debian/epistle.preinst` as text and assert the two literal
//! names the Rust store expects: the binary at `epistle-<version>/epistle` and
//! its digest at `epistle-<version>/epistle.sha256`. The Rust side keeps the
//! inverse assertion in `stack_rollback_store_tests::the_store_opens_the_two_
//! names_the_preinst_writes`. If either side moves, that file's test fails
//! here too.

use std::fs;
use std::path::{Path, PathBuf};

/// The repository root, as cargo hands it to an integration test.
fn root() -> PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Read one of the maintainer scripts, failing the test when it is absent.
fn read(relative: &str) -> String {
	let path = root().join(relative);
	fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// The 0-based line index of the first line containing `needle`.
fn line_of(text: &str, needle: &str) -> Option<usize> {
	text.lines().position(|line| line.contains(needle))
}

#[test]
fn the_preinst_writes_the_names_the_rollback_store_reads() {
	let preinst = read("debian/epistle.preinst");

	// The two lines the preinst uses to publish the pair. Either name being
	// renamed would silently break every rollback: the store asks for them
	// under exactly these literal names.
	let write_binary = line_of(&preinst, "$stage/epistle\"\n").or_else(|| {
		// Some shells split the redirect across lines; accept either.
		line_of(&preinst, "> \"$stage/epistle\"")
	});
	let write_digest = line_of(&preinst, "$stage/epistle.sha256\"");

	let binary = write_binary.unwrap_or_else(|| {
		panic!(
			"debian/epistle.preinst must write the binary to $stage/epistle under that exact \
			 name (the Rust store opens epistle-<version>/epistle); got:\n{preinst}"
		)
	});
	let digest = write_digest.unwrap_or_else(|| {
		panic!(
			"debian/epistle.preinst must write the digest to $stage/epistle.sha256 under that \
			 exact name (the Rust store opens epistle-<version>/epistle.sha256); got:\n{preinst}"
		)
	});
	assert!(
		binary < digest,
		"the preinst must write the binary before its digest (lines {} and {}); \
		 the digest is the SHA-256 of the binary, so its bytes must already exist",
		binary + 1,
		digest + 1
	);
}

#[test]
fn the_preinst_publishes_the_version_directory_under_exactly_that_name() {
	let preinst = read("debian/epistle.preinst");
	// The single rename that publishes the staged pair. Two renames (one for
	// the binary, one for the digest) re-introduce the gap R-02 was about; a
	// single one keeps the contract honest.
	let rename =
		line_of(&preinst, "mv -T -- \"$stage\" \"$rollback/epistle-$1\"").unwrap_or_else(|| {
			panic!(
				"debian/epistle.preinst must publish the staged pair with a single \
				 `mv -T -- \"$stage\" \"$rollback/epistle-$1\"` (two renames re-introduce \
				 the gap R-02 closed); got:\n{preinst}"
			)
		});
	// And the prune step trims to the two newest versions. It reads under
	// `epistle-*` so a stray file by that name would survive the prune.
	let prune = line_of(
		&preinst,
		"find \"$rollback\" -mindepth 1 -maxdepth 1 -type d -name 'epistle-*'",
	)
	.expect("the prune must name the publication prefix and require directory entries only");
	assert!(
		prune > rename,
		"the prune (line {}) must come after the rename (line {}) so a publication failure \
		 does not remove a selectable copy before the new one is in place",
		prune + 1,
		rename + 1
	);
}

#[test]
fn the_preinst_rejects_version_names_pick_cannot_choose() {
	let preinst = read("debian/epistle.preinst");
	// The validation the Rust side cannot afford to skip: `pick` only
	// understands `[0-9.]*`, so the script must refuse anything that would
	// reach the store as un-pickable bytes. R2-04 names this as a path that
	// saves a version `sort -V` can keep but `pick` cannot.
	let guard_line =
		line_of(&preinst, "case \"$1\" in").expect("the version case guard is present");
	// Find the validation pattern itself; it lives between `case "$1" in` and
	// the next `esac`, and is the line whose body rejects everything but the
	// allowed class.
	let validation_line = guard_line + 1;
	let validation = preinst
		.lines()
		.nth(validation_line)
		.expect("the validation clause sits on the line after `case \"$1\" in`");
	let allowed_class = validation
		.split("[!")
		.nth(1)
		.and_then(|rest| rest.split(']').next())
		.unwrap_or_default();
	assert!(
		!allowed_class.contains('~')
			&& !allowed_class.contains('+')
			&& !allowed_class.contains(':'),
		"the version-validation clause must not admit ~, + or : (a name like \
		 0.12.3~rc1, 1+0.12 or 0.12.3:backport is one `pick` cannot choose); got \
		 the class [{allowed_class:?}] in: {validation}"
	);
}

/// R2-03: the packaging tests in `tests/debian/` run the maintainer scripts
/// under `fakeroot`, because the scripts read root ownership off every path
/// they touch and an unprivileged run cannot exercise that without it. The
/// dependency was undeclared: the runner image happened to carry the tool, so
/// nothing said so, and the day it stopped, `cargo test` broke for a reason
/// unrelated to the code under test. This test reads the workflow and fails
/// when the package is missing, so the dependency stays visible and stays
/// true.
#[test]
fn the_ci_workflow_installs_fakeroot_for_the_packaging_tests() {
	let caller = read(".github/workflows/ci.yml");
	assert!(
		caller.contains("apt-packages: \"fakeroot\""),
		"ci.yml must pass apt-packages: \"fakeroot\" to the reusable test job: the \
		 packaging tests in tests/debian/ run the maintainer scripts under it, \
		 and without it the suite breaks for a reason unrelated to the code under \
		 test. See reusable-rust-ci.yml's apt-packages input."
	);

	// The reusable has to have the input and a step that acts on it, or the
	// caller's value goes nowhere and the run still breaks.
	let reusable = read(".github/workflows/reusable-rust-ci.yml");
	assert!(
		reusable.contains("apt-packages:"),
		"reusable-rust-ci.yml must declare an apt-packages input for the test job"
	);
	assert!(
		reusable.contains("APT_PACKAGES: ${{ inputs.apt-packages }}"),
		"reusable-rust-ci.yml's test job must read inputs.apt-packages, or the \
		 caller's fakeroot is declared and never installed"
	);
	assert!(
		reusable.contains("apt-get install -y --no-install-recommends $APT_PACKAGES"),
		"reusable-rust-ci.yml must actually install the packages the caller named"
	);
}
