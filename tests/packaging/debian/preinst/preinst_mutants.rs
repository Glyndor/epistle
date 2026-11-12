//! Regression tests that pin the package maintainer script against the
//! mutants the independent reviewer flagged. Each test below is the one
//! missing assertion that lets the mutant slip past the suite: a single
//! missing guard, or a missing refinement, that produces a same-green build
//! the suite does not catch. The tests are deliberately narrow and
//! reproducible, and each one runs the preinst as fakeroot does (the harness
//! passes it a setup line and the script that follows).

use super::preinst::script;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Pass the preinst through the harness with the given setup and arguments.
fn run_preinst(root: &Path, args: &[&str], setup: &str) -> std::process::Output {
	super::preinst::preinst(root, args, setup)
}

/// Path the harness uses for the rollback store.
fn store(root: &Path) -> std::path::PathBuf {
	super::preinst::store(root)
}

/// One saved version under the store, as the harness sees it.
fn generation(root: &Path, version: &str) -> std::path::PathBuf {
	super::preinst::generation(root, version)
}

/// Set up the test root the same way the preinst tests do, then add the
/// `usr/` and `usr/bin/` directories the kept-binary portion of the
/// preinst checks. The script substitution has to reach those paths before
/// running, so the runner below does the path rewriting the same way.
fn prepare_with_usr(root: &Path) {
	super::preinst::prepare(root);
	let usr = root.join("usr");
	let usr_bin = usr.join("bin");
	std::fs::create_dir_all(&usr_bin).unwrap();
	std::fs::set_permissions(&usr, std::fs::Permissions::from_mode(0o755)).unwrap();
	std::fs::set_permissions(&usr_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Run the preinst with `/usr` and `/usr/bin` substituted to the test
/// fixture. The default `script()` only rewrites `/usr/bin/epistle` and
/// `/var`, leaving `/usr` and `/usr/bin` as the host's. This variant is
/// what the kept-binary checks need when the test wants to control what
/// the script sees at those paths.
fn script_with_usr(root: &Path, name: &str) -> String {
	let mut prepared = script(root, name);
	prepared = prepared.replace("/usr", root.join("usr").to_str().unwrap());
	prepared
}

fn run_preinst_with_usr(root: &Path, args: &[&str], setup: &str) -> std::process::Output {
	let prepared = script_with_usr(root, "preinst");
	super::preinst::run(root, &prepared, args, setup)
}

/// M1 (the orphan staging directory the previous run left behind). The
/// preinst cleans `.stage-*` directories before staging a new one, so an
/// interrupted previous save does not pollute the next save's listing. A
/// mutant that drops the cleanup would leave the orphan behind; the test
/// plants one and asks the next save to produce the published generation,
/// then asserts the orphan is gone. dpkg serialises the maintainer scripts,
/// so the order the test simulates matches the real upgrade flow.
#[test]
fn an_orphan_stage_from_an_interrupted_save_is_cleaned_on_the_next_save() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	super::preinst::prepare(root);
	// Create the rollback store up front so the planted orphan has a parent.
	std::fs::create_dir(store(root)).unwrap();
	std::fs::set_permissions(store(root), std::fs::Permissions::from_mode(0o700)).unwrap();
	// A previous save was interrupted after `mktemp -d` but before the
	// `mv -T`. The `.stage-*` directory was left behind as it would be
	// after a partial run; populate it with the bytes that would have been
	// staged so the test detects a directory left behind, not an empty one.
	let interrupted = store(root).join(".stage-abcd1234");
	std::fs::create_dir(&interrupted).unwrap();
	std::fs::set_permissions(&interrupted, std::fs::Permissions::from_mode(0o700)).unwrap();
	std::fs::write(interrupted.join("epistle"), "interrupted").unwrap();

	let output = run_preinst(root, &["upgrade", "0.12.1"], "");
	assert!(output.status.success(), "{output:?}");

	assert!(
		!interrupted.exists(),
		"a previous run's staging directory must be cleaned before a new save starts; \
		 without the cleanup the operator's listing carries leftover staging entries; \
		 left behind: {:?}",
		std::fs::read_dir(store(root)).unwrap().collect::<Vec<_>>()
	);
	assert!(generation(root, "0.12.1").is_dir());
	assert!(super::preinst::generation_installs(root, "0.12.1"));
}

/// M10 (no validation of the version name `$2`). dpkg controls this value,
/// but the script's case guard is the only thing that stops a future change
/// from accepting a version that walks paths or breaks the listing. The test
/// runs the preinst with a `$2` like `../x` (after substitution) and asserts
/// the save fails. A regression that drops the case guard would publish the
/// bytes through the `cat > "$stage/epistle"` redirection.
#[test]
fn a_path_escape_in_the_version_name_is_refused() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	super::preinst::prepare(root);
	// A version containing `/` would be a path escape; the case guard must
	// refuse it before the staging is created. The test ships an argument
	// that, without a guard, would land a binary outside the rollback store.
	let output = run_preinst(root, &["upgrade", "../etc"], "");
	assert!(output.status.success(), "{output:?}");
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("could not keep"),
		"a path-escape version must surface as a refused save, not a successful one: {output:?}"
	);
	assert!(
		!store(root).join("../etc").exists() && !store(root).join("etc").exists(),
		"the script must not have written a binary under store/../etc or store/etc"
	);
	let listings = super::preinst::listing(root);
	for entry in &listings {
		assert!(
			entry.starts_with("epistle-") && !entry.contains('/'),
			"every entry under the store must be a regular published pair, got {entry:?}"
		);
	}
}

/// M12 (no `chmod 0700` of an existing rollback store). An operator who
/// built the store with an older release that left it at 0750 would see
/// rollback refuse to open it (Rust checks mode == 0700), and the suite
/// would stay green because nothing checked the mode. The test plants a
/// 0750 store and asks for a save; the only thing that fixes the mode is
/// the maintainer script's `chmod 0700` on the store.
#[test]
fn an_existing_store_at_0750_is_corrected_to_0700() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	super::preinst::prepare(root);
	std::fs::create_dir(store(root)).unwrap();
	// Mode 0750 is root-owned, group readable, others denied: it passes the
	// existing bitwise check (no write bit for group or other), but the
	// Store in Rust refuses anything that is not exactly 0700. The maintainer
	// script's `chmod 0700` is what brings the directory back into shape.
	std::fs::set_permissions(store(root), std::fs::Permissions::from_mode(0o755)).unwrap();
	let before = std::fs::metadata(store(root)).unwrap().permissions().mode() & 0o777;
	let output = run_preinst(root, &["upgrade", "0.12.1"], "");
	assert!(output.status.success(), "{output:?}");
	let after = std::fs::metadata(store(root)).unwrap().permissions().mode() & 0o777;
	assert_eq!(
		after, 0o700,
		"the rollback store must end at mode 0700 once the maintainer script has run; \
		 before={before:o} after={after:o} output: {output:?}"
	);
	assert!(generation(root, "0.12.1").is_dir());
}

/// M13 (no `for parent in /usr /usr/bin` checks). The only source of bytes
/// the maintainer script trusts is `/usr/bin/epistle`; both parents must be
/// root-owned and refuse group or other write. The test opens the kept-
/// binary portion of the preinst against a fixture where the directory the
/// script reads is mode 0777. Without the guard the preinst would read any
/// bytes that landed there and write them into the store, which is the root
/// of the trust assumption.
#[test]
fn a_world_writable_usr_bin_is_refused_when_saving_the_binary() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	prepare_with_usr(root);
	// `chmod 0777 usr/bin` makes the parent directory refuse the guard:
	// `mode & 022` is non-zero, so the `for parent in /usr /usr/bin` check
	// returns 1 and the save is refused. The Rust side never sees the pair.
	let output = run_preinst_with_usr(root, &["upgrade", "0.12.1"], "chmod 0777 usr/bin");
	assert!(output.status.success(), "{output:?}");
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("could not keep"),
		"a writable /usr/bin must surface as a refused save: {output:?}"
	);
	assert!(
		!store(root).join("epistle-0.12.1").exists(),
		"the save must not reach the store when /usr/bin is writable; listing: {:?}",
		super::preinst::listing(root)
	);
}

/// M14 (no `-type d` on the prune find). A regression that drops `-type d`
/// would also match stray files under the `epistle-*` prefix and hand them
/// to `rm -rf`. The test plants a stray *file* under that prefix whose
/// version sorts OLDER than the three real generations, so a prune that
/// does not restrict itself to directories puts it inside the `head -n -2`
/// window and removes it. The correct implementation matches directories
/// only, counts three generations, and leaves the file alone.
#[test]
fn the_prune_keeps_a_stray_file_under_the_version_prefix() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	super::preinst::prepare(root);
	std::fs::create_dir(store(root)).unwrap();
	std::fs::set_permissions(store(root), std::fs::Permissions::from_mode(0o700)).unwrap();
	// A file named with the oldest version under the prefix. It is not a
	// generation directory the rollback command can open. Three later saves
	// make four entries under the prefix, and `sort -V | head -n -2` then
	// names this file as one of the entries to remove, so only the
	// `-type d` restriction keeps it.
	let stray = store(root).join("epistle-0.0.0");
	std::fs::write(&stray, "stray").unwrap();
	for version in ["0.12.1", "0.12.2", "0.12.3"] {
		let output = run_preinst(root, &["upgrade", version], "");
		assert!(output.status.success(), "{version}: {output:?}");
	}
	assert!(
		stray.is_file(),
		"a stray file under the version prefix is not a generation directory and must \
		 still be there after the prune step; its version sorts older than the three \
		 saved ones, so a prune without `-type d` would have handed it to `rm -rf`. \
		 Listing: {:?}",
		std::fs::read_dir(store(root)).unwrap().collect::<Vec<_>>()
	);
}

/// The exclusive temporary the preinst creates is also the directory it
/// stages the binary and its digest inside. A regression that calls
/// `mktemp -d` (so the existing `the_exclusive_temporary_is_random...`
/// test sees the call) but then ignores the return value to write into a
/// fixed name (`.stage-static`) would publish the binary somewhere the
/// cleanup does not look. This test plants a sentinel file inside the
/// directory the wrapper reports as the mktemp result; if the preinst
/// actually uses that path for staging, the sentinel rides through the
/// single rename and ends up next to the published binary. A saboteur
/// that fixed the staging path to `.stage-static` would publish without
/// the sentinel, and the test fails because that file is absent from the
/// final generation.
#[test]
fn the_staging_directory_uses_what_mktemp_returned() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	super::preinst::prepare(root);
	let tools_dir = root.join("tools");
	std::fs::create_dir_all(&tools_dir).unwrap();
	// Wrap `mktemp` so the directory it returns is observable from the
	// test. The wrapper drops a sentinel file in the just-created
	// directory; whatever path the preinst actually uses for staging
	// will carry the sentinel through the `mv -T` publish and the test
	// can read it back inside the published generation.
	let mktemp_log = root.join("mktemp.sentinel");
	let body = format!(
		"#!/bin/sh\n\
		 name=$(/usr/bin/mktemp \"$@\") || exit $?\n\
		 printf '%s' \"$name\" > {log}\n\
		 printf 'mktemp-sentinel\\n' > \"$name/mktemp-sentinel\"\n\
		 printf '%s' \"$name\"\n",
		log = mktemp_log.display()
	);
	let wrap_path = tools_dir.join("mktemp");
	let _ = std::fs::remove_file(&wrap_path);
	std::fs::write(&wrap_path, body).unwrap();
	std::fs::set_permissions(&wrap_path, std::fs::Permissions::from_mode(0o755)).unwrap();

	let output = run_preinst(root, &["upgrade", "0.12.1"], "");
	assert!(output.status.success(), "{output:?}");

	let mktemp_made = std::fs::read_to_string(&mktemp_log).unwrap_or_else(|error| {
		panic!("the mktemp wrapper did not record the staging path: {error}");
	});
	assert!(
		!mktemp_made.is_empty(),
		"the mktemp wrapper must record the path it returned; got an empty log: {output:?}"
	);

	// The single `mv -T` published the staging directory under the version
	// name. If the staging directory was the one mktemp returned, the
	// sentinel ended up there. A saboteur that ignored mktemp and used a
	// fixed name (e.g. `.stage-static`) would publish that fixed name and
	// the sentinel would still be at mktemp's return path, not at the
	// generation directory.
	let published = generation(root, "0.12.1");
	let sentinel = published.join("mktemp-sentinel");
	assert!(
		sentinel.is_file(),
		"the staging directory mktemp returned ({mktemp_made:?}) must carry the binary, so \
		 the sentinel the wrapper dropped there must ride through `mv -T` and end up inside \
		 the published generation {published:?}; a saboteur that ignored mktemp's return \
		 and used a fixed staging name (`.stage-static`) would publish elsewhere and this \
		 assertion would catch it. Listing: {:?}",
		std::fs::read_dir(store(root)).unwrap().collect::<Vec<_>>()
	);
	assert_eq!(
		std::fs::read_to_string(&sentinel).unwrap_or_default(),
		"mktemp-sentinel\n",
		"the sentinel written into the directory mktemp returned must be intact at the \
		 published generation: the staging used the path mktemp gave"
	);
}
