//! Exercise how the package publishes a saved binary: the exclusive temporary
//! it stages it in, and what an interrupted or refused publication leaves.

use super::preinst::{generation, generation_installs, listing, preinst, prepare, store};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// The path the harness puts first in PATH.
fn tool(root: &Path, name: &str) -> PathBuf {
	root.join("tools").join(name)
}

/// The copy of a tool Debian ships, when the host also has a prefixed one.
fn gnu(name: &str) -> String {
	let prefixed = format!("/usr/bin/gnu{name}");
	if Path::new(&prefixed).exists() {
		prefixed
	} else {
		format!("/usr/bin/{name}")
	}
}

/// Answer a tool call with `body` instead of the tool, ahead of every other
/// copy in PATH.
fn wrap(root: &Path, name: &str, body: &str) {
	let path = tool(root, name);
	std::fs::create_dir_all(root.join("tools")).unwrap();
	// Never write through the link the harness left for the real tool.
	let _ = std::fs::remove_file(&path);
	std::fs::write(&path, body).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Record what the exclusive temporary was asked for, what it was given, and
/// what the tool left behind, then answer like the tool itself.
fn record_mktemp(root: &Path) -> PathBuf {
	let log = root.join("mktemp.calls");
	wrap(
		root,
		"mktemp",
		&format!(
			"#!/bin/sh\necho \"args:$*\" >> {log}\nname=$({real} \"$@\") || exit $?\n\
			 echo \"made:$name\" >> {log}\necho \"kind:$(stat -c '%F %a' -- \"$name\")\" >> {log}\n\
			 echo \"$name\"\n",
			log = log.display(),
			real = gnu("mktemp")
		),
	);
	log
}

/// Fail the renames from the nth call on, and record how many were tried.
fn fail_renames(root: &Path, nth: usize) -> PathBuf {
	let calls = root.join("rename.calls");
	wrap(
		root,
		"mv",
		&format!(
			"#!/bin/sh\ncount=$(cat {calls} 2>/dev/null || echo 0)\ncount=$((count + 1))\n\
			 echo \"$count\" > {calls}\nif [ \"$count\" -ge {nth} ]; then exit 1; fi\n\
			 exec {real} \"$@\"\n",
			calls = calls.display(),
			nth = nth,
			real = gnu("mv")
		),
	);
	calls
}

#[test]
fn a_failed_publication_leaves_the_previous_generation_installable() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	prepare(root);
	assert!(preinst(root, &["upgrade", "0.12.1"], "").status.success());
	assert!(generation_installs(root, "0.12.1"));
	let saved = listing(root);

	// The rename that publishes the next version fails.
	let calls = fail_renames(root, 1);
	let output = preinst(root, &["upgrade", "0.12.2"], "");
	assert!(output.status.success(), "{output:?}");
	assert!(
		String::from_utf8_lossy(&output.stderr).contains("could not keep"),
		"{output:?}"
	);
	assert_eq!(
		std::fs::read_to_string(&calls).unwrap().trim(),
		"1",
		"the publishing rename was tried and failed"
	);
	assert_eq!(
		listing(root),
		saved,
		"a failed publication leaves no entry and no staged leftovers"
	);
	assert!(generation_installs(root, "0.12.1"));
	assert_eq!(
		std::fs::read_to_string(generation(root, "0.12.1").join("epistle")).unwrap(),
		"installed binary"
	);
}

#[test]
fn a_saved_version_is_published_with_a_single_rename() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	prepare(root);
	assert!(preinst(root, &["upgrade", "0.12.1"], "").status.success());

	// The second rename fails: a copy published in two steps keeps the digest
	// of one binary beside the bytes of another.
	let calls = fail_renames(root, 2);
	let output = preinst(root, &["upgrade", "0.12.2"], "");
	assert!(output.status.success(), "{output:?}");
	assert_eq!(
		std::fs::read_to_string(&calls).unwrap().trim(),
		"1",
		"the whole generation reaches the store by one rename"
	);
	assert!(
		generation_installs(root, "0.12.2"),
		"a version that could not be published whole must not be selectable"
	);
	assert!(generation_installs(root, "0.12.1"));
}

#[test]
fn a_version_already_saved_is_not_replaced_by_another_binary() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	prepare(root);
	assert!(preinst(root, &["upgrade", "0.12.1"], "").status.success());

	// The operator rolled back by hand, so dpkg still records the newer
	// version and the next upgrade saves other bytes under the saved name.
	std::fs::write(root.join("epistle"), "rolled back binary").unwrap();
	fail_renames(root, 2);
	let output = preinst(root, &["upgrade", "0.12.1"], "");
	assert!(output.status.success(), "{output:?}");
	assert_eq!(
		String::from_utf8_lossy(&output.stderr),
		"",
		"keeping the copy already saved is not a failure: {output:?}"
	);
	assert!(
		generation_installs(root, "0.12.1"),
		"the saved copy must keep installing after a refused save"
	);
	assert_eq!(
		std::fs::read_to_string(generation(root, "0.12.1").join("epistle")).unwrap(),
		"installed binary"
	);
}

#[test]
fn a_stale_entry_that_is_no_generation_does_not_block_the_new_one() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	prepare(root);
	std::fs::create_dir(store(root)).unwrap();
	std::fs::set_permissions(store(root), std::fs::Permissions::from_mode(0o700)).unwrap();
	// Files under the version name are not a generation the rollback command
	// can read, so they must not be kept as if they were one saved copy.
	std::fs::write(store(root).join("epistle-0.12.1"), "flat copy").unwrap();
	std::fs::write(store(root).join("epistle-0.12.1.sha256"), "stale\n").unwrap();
	let output = preinst(root, &["upgrade", "0.12.1"], "");
	assert!(output.status.success(), "{output:?}");
	assert_eq!(listing(root), ["epistle-0.12.1"]);
	assert!(
		generation_installs(root, "0.12.1"),
		"the stale entry must not be taken for the saved copy"
	);
	assert_eq!(
		std::fs::read_to_string(generation(root, "0.12.1").join("epistle")).unwrap(),
		"installed binary"
	);
}

#[test]
fn the_exclusive_temporary_is_random_private_and_really_created() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	prepare(root);
	let log = record_mktemp(root);
	let output = preinst(root, &["upgrade", "0.12.1"], "");
	assert!(output.status.success(), "{output:?}");

	let calls = std::fs::read_to_string(&log)
		.unwrap_or_else(|error| panic!("the preinst must ask for an exclusive temporary: {error}"));
	let mut lines = calls.lines();
	let (asked, made, kind) = (
		lines.next().unwrap_or_default(),
		lines.next().unwrap_or_default(),
		lines.next().unwrap_or_default(),
	);
	assert!(
		lines.next().is_none(),
		"one exclusive temporary per saved version: {calls}"
	);
	// The temporary is asked for by a random name inside the store.
	let asked = asked.strip_prefix("args:").unwrap_or_default();
	let template = asked.split_whitespace().last().unwrap_or_default();
	assert!(
		asked.contains("-d"),
		"a generation is staged whole: {asked}"
	);
	assert!(
		template.ends_with("XXXXXXXXXX"),
		"the temporary name must be random, not a fixed one: {template}"
	);
	assert!(
		template.starts_with(store(root).to_str().unwrap()),
		"the temporary stays inside the store: {template}"
	);
	// The tool created it, exclusively, private, and not as a link.
	let created = made.strip_prefix("made:").unwrap_or_default();
	assert_ne!(
		created, template,
		"a random name, not the template: {calls}"
	);
	assert!(
		created.starts_with(store(root).to_str().unwrap()),
		"the temporary stays inside the store: {created}"
	);
	let kind = kind.strip_prefix("kind:").unwrap_or_default();
	let (found, perms) = kind.split_once(' ').unwrap_or((kind, ""));
	assert_eq!(found, "directory", "not a link or another type: {calls}");
	assert_eq!(perms, "700", "no other user reaches the temporary: {calls}");
	assert!(
		generation_installs(root, "0.12.1"),
		"the staged pair was published: {calls}"
	);
}

#[test]
fn a_failure_to_create_the_temporary_saves_nothing_and_keeps_what_is_saved() {
	let dir = tempfile::tempdir().unwrap();
	let root = dir.path();
	prepare(root);
	assert!(preinst(root, &["upgrade", "0.12.1"], "").status.success());
	assert!(generation_installs(root, "0.12.1"));
	let saved = listing(root);

	// The exclusive temporary cannot be created at all.
	wrap(root, "mktemp", "#!/bin/sh\nexit 1\n");
	let output = preinst(root, &["upgrade", "0.12.2"], "");
	assert!(output.status.success(), "{output:?}");
	assert!(
		String::from_utf8_lossy(&output.stderr).contains("could not keep"),
		"{output:?}"
	);
	assert_eq!(
		listing(root),
		saved,
		"without the exclusive temporary nothing is published"
	);
	assert!(generation_installs(root, "0.12.1"));
}
