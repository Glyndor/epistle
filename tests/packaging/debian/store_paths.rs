//! Cross-file contract tests for the package maintainer script and the Rust
//! rollback store. A regression on either side breaks the published pair the
//! operator reaches through `stack rollback`, and the only place where both
//! names live together is here.
//!
//! The tests read `debian/epistle.preinst` as text and assert the two literal
//! names the Rust store expects: the binary at `epistle-<version>/epistle` and
//! its digest at `epistle-<version>/epistle.sha256`. The Rust side keeps the
//! inverse assertion in `src/cli/stack/rollback/store/tests/base.rs`
//! (`the_store_source_keeps_the_published_names`). If either side moves,
//! that file's test fails here too.

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

/// The class the script keeps must be the class `pick` parses, no wider and
/// no narrower. `numbers()` splits the name on dots and reads every part as
/// an integer, so `[0-9.]` is the whole language: `0.12.3-1`, `0.12.3a`,
/// `0.12.3~rc1` and `1:0.12+1` are names `sort -V` keeps and `stack rollback`
/// can never offer, and a name that starts or ends in a dot, or carries two
/// dots in a row, parses to no version either.
#[test]
fn the_preinst_version_class_is_the_one_pick_parses() {
	let preinst = read("debian/epistle.preinst");
	let guard_line =
		line_of(&preinst, "case \"$1\" in").expect("the version case guard is present");
	let clause = preinst
		.lines()
		.nth(guard_line + 1)
		.expect("the validation clause sits on the line after `case \"$1\" in`");
	let allowed_class = clause
		.split("[!")
		.nth(1)
		.and_then(|rest| rest.split(']').next())
		.unwrap_or_default();
	assert_eq!(
		allowed_class, "0-9.",
		"the saved version name must be the class `pick` parses and nothing else: digits \
		 and dots. A wider class saves names the rollback command cannot read back \
		 (a Debian revision such as 0.12.3-1, a tilde or a colon all reach the store \
		 today and none of them is selectable). Got the class [{allowed_class:?}] in: \
		 {clause}"
	);
	assert!(
		clause.contains("''"),
		"the empty name must be refused too: the dispatcher skips it, so the guard is \
		 the only thing that keeps a bare `epistle-` directory out of the store. Got: \
		 {clause}"
	);
}

/// The class as the package behaves, not as it reads. Each name `pick`
/// cannot parse is offered to the real preinst and must come back as a
/// refused save with an empty store, and the name the package really carries
/// must still be kept: a guard that refuses everything would pass the loop.
#[test]
fn only_versions_pick_can_choose_reach_the_store() {
	for refused in [
		"0.12.3-1",
		"0.12.3a",
		"0.12.3~rc1",
		"1:0.12+1",
		".12.3",
		"12.3.",
		"1..2",
		"0.12.99999999999999999999",
	] {
		let dir = tempfile::tempdir().unwrap();
		let root = dir.path();
		super::preinst::prepare(root);
		let output = super::preinst::preinst(root, &["upgrade", refused], "");
		assert!(output.status.success(), "{refused}: {output:?}");
		assert!(
			String::from_utf8_lossy(&output.stderr).contains("could not keep"),
			"{refused:?} is a name `pick` cannot parse, so the save must be refused with \
			 that warning: {output:?}"
		);
		assert!(
			super::preinst::listing(root).is_empty(),
			"{refused:?} must not reach the store: `sort -V` would keep it as a slot \
			 `stack rollback` can never choose. Listing: {:?}",
			super::preinst::listing(root)
		);
	}

	let dir = tempfile::tempdir().unwrap();
	super::preinst::prepare(dir.path());
	let output = super::preinst::preinst(dir.path(), &["upgrade", "0.12.1"], "");
	assert!(output.status.success(), "0.12.1: {output:?}");
	assert!(
		super::preinst::generation_installs(dir.path(), "0.12.1"),
		"the class must still keep the version the package carries: a guard that refused \
		 every name would empty the store instead"
	);
	assert!(
		keep_binary_refuses(dir.path(), ""),
		"the empty name must be refused by the guard, not only skipped by the dispatcher"
	);
}

/// Whether `epistle_keep_binary` refuses `version` on its own. The dispatcher
/// never calls it without a version, so the driver calls it the way the
/// dispatcher would once the store exists.
fn keep_binary_refuses(root: &Path, version: &str) -> bool {
	let script = read("debian/epistle.preinst")
		.replace("/usr/bin/epistle", root.join("epistle").to_str().unwrap())
		.replace("/var", root.join("var").to_str().unwrap());
	let driver = script
		.strip_suffix("exit 0\n")
		.expect("debian/epistle.preinst ends with `exit 0`")
		.to_owned()
		+ &format!("\nepistle_keep_binary '{version}'\n");
	// The harness runs the driver under `set -e`, so a refused helper leaves
	// the shell with its status.
	!super::preinst::run(root, &driver, &["install"], "")
		.status
		.success()
}

/// The body of one job of the reusable workflow: the lines under its `  <name>:`
/// header, up to the next job header. Reading the whole file as one string
/// cannot tell which job a step sits in, and a step in the wrong job reads as
/// a satisfied dependency.
fn job(reusable: &str, name: &str) -> String {
	let lines: Vec<&str> = reusable.lines().collect();
	let start = lines
		.iter()
		.position(|line| *line == format!("  {name}:"))
		.unwrap_or_else(|| panic!("reusable-rust-ci.yml must keep the {name:?} job"));
	lines[start + 1..]
		.iter()
		.take_while(|line| line.trim().is_empty() || line.starts_with("    "))
		.copied()
		.collect::<Vec<&str>>()
		.join("\n")
}

/// R2-03: the packaging tests in `tests/packaging/debian/` run the maintainer scripts
/// under `fakeroot`, because the scripts read root ownership off every path
/// they touch and an unprivileged run cannot exercise that without it. The
/// dependency was undeclared: the runner image happened to carry the tool, so
/// nothing said so, and the day it stopped, `cargo test` broke for a reason
/// unrelated to the code under test.
///
/// Every job that runs the workspace suite needs it, and that is two: `test`,
/// and `coverage`, which runs the same tests under `cargo llvm-cov`. Reading
/// the file as one string would accept a step that lives in only one of them,
/// which is how the coverage job stayed without `fakeroot` for a release.
#[test]
fn the_ci_workflow_installs_fakeroot_for_the_packaging_tests() {
	let caller = read(".github/workflows/ci.yml");
	assert!(
		caller.contains("apt-packages: \"fakeroot\""),
		"ci.yml must pass apt-packages: \"fakeroot\" to the reusable jobs: the \
		 packaging tests in tests/packaging/debian/ run the maintainer scripts under it, \
		 and without it the suite breaks for a reason unrelated to the code under \
		 test. See reusable-rust-ci.yml's apt-packages input."
	);

	let reusable = read(".github/workflows/reusable-rust-ci.yml");
	assert!(
		reusable.contains("apt-packages:"),
		"reusable-rust-ci.yml must declare an apt-packages input for the jobs that \
		 run the suite"
	);
	for name in ["test", "coverage"] {
		let body = job(&reusable, name);
		assert!(
			body.contains("APT_PACKAGES: ${{ inputs.apt-packages }}"),
			"reusable-rust-ci.yml's {name:?} job must read inputs.apt-packages, or \
			 the caller's fakeroot is declared and never installed there. Job body:\n{body}"
		);
		assert!(
			body.contains("sudo apt-get install -y --no-install-recommends $APT_PACKAGES"),
			"reusable-rust-ci.yml's {name:?} job must actually install the packages \
			 the caller named, or it runs the packaging tests without fakeroot. \
			 Job body:\n{body}"
		);
	}
}
