//! Opening what the maintainer script published, with a real uid 0 inside a user namespace.

use super::*;

/// Set by the outer run for the inner one, so this test knows it is the pass
/// that owns a real uid 0.
const ROOT_SANDBOX: &str = "EPISTLE_ROLLBACK_ROOT_SANDBOX";

/// What the inner run prints before it does anything. Without it in the
/// output the outer run knows the sandbox never reached the test, and says it
/// skipped rather than counting a pass.
const SANDBOX_ENTERED: &str = "rollback store sandbox: entered";

/// The name this test answers to when it re-executes itself inside the
/// sandbox, as a filter for the test harness.
const SANDBOXED: &str = "the_store_opens_the_generation_the_preinst_publishes";

/// The bytes planted as `/usr/bin/epistle`, so what the store yields back is
/// recognisable.
const INSTALLED: &[u8] = b"the binary the preinst kept\n";

/// Opens what the package maintainer script really published, with a real
/// uid 0.
///
/// The fixtures above only reach that half where the test run is root, so in a
/// normal CI job the store never opened a generation end to end and a rename
/// on the Rust side stayed green (R2-01). `fakeroot` cannot fill the gap: it
/// rewrites what a wrapped command reports, not what the kernel reports for a
/// descriptor this process holds. A user namespace can, because uid 0 is real
/// inside it, so this test re-runs itself under `bwrap` or `unshare` and reads
/// the generation the preinst published from its own tree. Where no sandbox
/// is available the run says it skipped, in the open.
#[test]
fn the_store_opens_the_generation_the_preinst_publishes() {
	if std::env::var_os(ROOT_SANDBOX).is_some() {
		println!("{SANDBOX_ENTERED}");
		return publish_and_read();
	}
	let executable = match std::env::current_exe() {
		Ok(executable) => executable,
		Err(error) => return skip(&format!("this test binary has no path ({error})")),
	};
	let mut why = Vec::new();
	for sandbox in sandboxes() {
		let mut arguments = sandbox.clone();
		arguments.push(executable.display().to_string());
		arguments.push(SANDBOXED.to_owned());
		arguments.push("--nocapture".to_owned());
		let run = std::process::Command::new(&sandbox[0])
			.args(&arguments[1..])
			.env(ROOT_SANDBOX, "1")
			// The sandbox gives the inner run its own `/tmp`; a TMPDIR from
			// outside it would be the read-only part.
			.env_remove("TMPDIR")
			.output();
		let run = match run {
			Ok(run) => run,
			Err(error) => {
				why.push(format!("{} would not run ({error})", sandbox[0]));
				continue;
			}
		};
		let output = String::from_utf8_lossy(&run.stdout);
		if !output.contains(SANDBOX_ENTERED) {
			why.push(format!(
				"{} did not reach the test ({})",
				sandbox[0],
				String::from_utf8_lossy(&run.stderr).trim()
			));
			continue;
		}
		assert!(
			run.status.success(),
			"the store must open the generation the preinst published, run as a real uid 0 \
			 inside {}\n{output}\n{}",
			sandbox[0],
			String::from_utf8_lossy(&run.stderr)
		);
		println!("{}: {output}", sandbox[0]);
		return;
	}
	skip(&why.join("; "));
}

/// Runs the real maintainer script against a tree of our own paths and reads
/// back what it published. Only reachable with a real uid 0.
fn publish_and_read() {
	let directory = tempfile::tempdir().unwrap();
	let root = directory.path();
	plant(root);
	let script = root.join("epistle.preinst");
	std::fs::write(&script, remapped(root)).unwrap();
	let output = std::process::Command::new("sh")
		.arg(&script)
		.args(["upgrade", "0.12.1"])
		.current_dir(root)
		.output()
		.expect("the sandbox runs the maintainer script");
	assert!(
		output.status.success(),
		"the preinst must save a copy: {output:?}"
	);

	let store = root.join("var/lib/epistle-rollback");
	assert!(
		store.is_dir(),
		"the preinst must have prepared the store it publishes into: {output:?}"
	);
	let generation = store.join("epistle-0.12.1");
	assert_eq!(
		mode(&generation),
		0o700,
		"the preinst must publish a private generation directory: {output:?}"
	);
	assert_eq!(
		mode(&generation.join("epistle")),
		0o755,
		"the copy must keep the mode of the binary it took: {output:?}"
	);
	assert_eq!(
		mode(&generation.join("epistle.sha256")) & 0o022,
		0,
		"no other user may write the digest: {output:?}"
	);

	let store = Store {
		dir: File::open(&store).unwrap(),
		owner: ROOT,
	};
	let (chosen, mut binary) = store
		.select("0.12.2", None)
		.expect("the store must choose the generation the preinst published");
	assert_eq!(chosen, "epistle-0.12.1");
	let mut kept = Vec::new();
	binary.read_to_end(&mut kept).unwrap();
	assert_eq!(
		kept, INSTALLED,
		"the verified descriptor must yield the bytes the preinst copied"
	);
	assert!(
		store.select("0.12.2", Some("0.12.1")).is_ok(),
		"the same generation must answer to the explicit version too"
	);
}

/// The tree the maintainer script walks: the binary it copies and the
/// `/usr` and `/var/lib` parents it checks first. Every mode is set here:
/// `tempfile` leaves the temporary root on the umask of the run, and a
/// group writable root is refused by the parent walk for a reason that has
/// nothing to do with the store.
fn plant(root: &Path) {
	std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755)).unwrap();
	for parent in [
		"usr",
		"usr/bin",
		"var",
		"var/lib",
		"var/lib/glyndor/epistle",
	] {
		std::fs::create_dir_all(root.join(parent)).unwrap();
		std::fs::set_permissions(root.join(parent), std::fs::Permissions::from_mode(0o755))
			.unwrap();
	}
	let binary = root.join("usr/bin/epistle");
	std::fs::write(&binary, INSTALLED).unwrap();
	std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// The maintainer script as it is shipped, with the tree it walks moved
/// under `root`. The replacements go through placeholders, or the path that
/// stands in for `/usr` would be rewritten again by the same pass that
/// rewrites the rest. The walk over `/`, `/var` and `/var/lib` moves with
/// them: inside the sandbox the filesystem root belongs to nobody, so the
/// shipped script would stop there for a reason that has nothing to do with
/// the store.
fn remapped(root: &Path) -> String {
	let shipped = Path::new(env!("CARGO_MANIFEST_DIR")).join("debian/epistle.preinst");
	let script = std::fs::read_to_string(&shipped)
		.unwrap_or_else(|error| panic!("read {}: {error}", shipped.display()));
	let relocated = script.replace(
		"for parent in / /var /var/lib;",
		"for parent in @ROOT@ @VAR@ @VAR@/lib;",
	);
	assert!(
		relocated.contains("for parent in @ROOT@"),
		"debian/epistle.preinst no longer walks / /var /var/lib, so this fixture no \
		 longer mirrors the script it runs"
	);
	relocated
		.replace("/usr/bin/epistle", "@EPIS@")
		.replace("/usr", "@USR@")
		.replace("/var", "@VAR@")
		.replace("@EPIS@", root.join("usr/bin/epistle").to_str().unwrap())
		.replace("@USR@", root.join("usr").to_str().unwrap())
		.replace("@VAR@", root.join("var").to_str().unwrap())
		.replace("@ROOT@", root.to_str().unwrap())
}

/// The sandboxes that hand this process a real uid 0, in the order they are
/// tried. Both need user namespaces to be allowed; a machine that forbids
/// them simply has none.
fn sandboxes() -> Vec<Vec<String>> {
	let bwrap = [
		"bwrap",
		"--unshare-user",
		"--uid",
		"0",
		"--gid",
		"0",
		"--ro-bind",
		"/",
		"/",
		"--tmpfs",
		"/tmp",
		"--dev",
		"/dev",
		"--proc",
		"/proc",
		"--chdir",
		"/",
	];
	let unshare = ["unshare", "--map-root-user"];
	[bwrap.as_slice(), unshare.as_slice()]
		.iter()
		.map(|words| words.iter().map(|word| (*word).to_owned()).collect())
		.filter(|words: &Vec<String>| on_path(&words[0]))
		.collect()
}

/// Whether `tool` is a program this run can start.
fn on_path(tool: &str) -> bool {
	std::env::var_os("PATH").is_some_and(|path| {
		std::env::split_paths(&path).any(|directory| directory.join(tool).is_file())
	})
}

fn skip(why: &str) {
	println!(
		"skipped: {why}, so no root sandbox could open the published generation \
		 here; the fixtures above covered the refusal only"
	);
}

/// The two literals the package script writes must appear as literal strings
/// inside the Store's lookup calls. Without this, a regression that opened the
/// pair under a different name (e.g. `epistle-bin`, `epistle.digest`) would
/// still find a directory listing that matches the script and let the
/// contract drift without any test going red. The integration test in
/// `tests/packaging/debian_isolated_user.rs` reads the script and asserts the
/// corresponding strings there. This stays as the pin that runs everywhere:
/// the sandboxed read runs only where a root namespace is available.
#[test]
fn the_store_source_keeps_the_published_names() {
	let source = include_str!("../../mod.rs");
	for needle in ["\"epistle\"", "\"epistle.sha256\""] {
		assert!(
			source.contains(needle),
			"src/cli/stack/rollback/store/mod.rs must open the published file under {needle:?}; \
			 the package maintainer script writes exactly that name, and a rename here would \
			 silently break every rollback"
		);
	}
}

#[test]
fn ownership_type_and_permissions_must_all_be_trusted() {
	assert!(protected(true, 0, 0, 0o755));
	for (kind, uid, mode) in [
		(false, 0, 0o755),
		(true, 1000, 0o755),
		(true, 0, 0o775),
		(true, 0, 0o757),
	] {
		assert!(!protected(kind, 0, uid, mode));
	}
	assert!(protected_directory(true, ROOT, 0, 0, 0o755, false));
	assert!(protected_directory(true, ROOT, 0, 0, 0o700, true));
	for (kind, uid, gid, mode, private) in [
		(false, 0, 0, 0o700, true),
		(true, 1000, 0, 0o700, true),
		(true, 0, 1000, 0o700, true),
		(true, 0, 0, 0o777, false),
		(true, 0, 0, 0o755, true),
	] {
		assert!(!protected_directory(kind, ROOT, uid, gid, mode, private));
	}
}
