//! Helpers shared by `tests/stack_podup.rs` and
//! `tests/stack_podup_errors.rs`. Each `tests/*.rs` is its own
//! Cargo binary, so the helpers are pulled in with a `#[path]`
//! attribute. Anything in here is plumbing: writing a stub
//! `podup` to a temp dir, recording its argv, and spawning the
//! real `epistle` binary with the stub first on `PATH`. Every test
//! that drives a subcommand builds a shim and checks what came
//! out; the helpers keep that boilerplate in one place so the
//! test files stay readable and stay under the 500-code-line cap.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// Each test binary picks a subset of the helpers; the rest are
// dead code from the compiler's point of view. Keeping the whole
// set in one file beats a near-duplicate copy in each test
// binary; the warning is a tax on the layout, not a real defect.
#[allow(dead_code)]
pub(crate) fn binary() -> &'static Path {
	Path::new(env!("CARGO_BIN_EXE_epistle"))
}

/// Compose a `path1:path2:...` string from the temp dir and the
/// inherited `PATH`, with the temp dir first so the stub shadows any
/// host-installed `podup`. The test must not mutate the process-wide
/// `PATH`, so the value is only set on the spawned child.
/// Compose a `path1:path2:...` string from the temp dir and the
/// inherited `PATH`, with the temp dir first so the stub shadows any
/// host-installed `podup`. The test must not mutate the process-wide
/// `PATH`, so the value is only set on the spawned child.
#[allow(dead_code)]
pub(crate) fn path_with_shim_first(shim_dir: &Path) -> std::ffi::OsString {
	let system_path = std::env::var_os("PATH").unwrap_or_default();
	let mut combined = shim_dir.as_os_str().to_owned();
	if !system_path.is_empty() {
		combined.push(":");
		combined.push(&system_path);
	}
	combined
}

/// Write `body` to `<shim_dir>/podup` and mark it executable.
#[allow(dead_code)]
pub(crate) fn write_podup_shim(shim_dir: &Path, body: &str) -> PathBuf {
	std::fs::create_dir_all(shim_dir).expect("mkdir shim dir");
	let path = shim_dir.join("podup");
	std::fs::write(&path, body).expect("write shim");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
		.expect("chmod 0755 on shim");
	path
}

/// Install a `podup` shim and probe it with `sh -n` so a syntax
/// error in the body surfaces as a clear test panic instead of an
/// opaque "exit 2" from the child. The probe is the cheapest way
/// to keep the generated heredocs honest: a stray backtick or
/// unescaped quote would otherwise be a one-line diff in
/// `ps_shim` that turns every `ps_*` test red at once.
#[allow(dead_code)]
pub(crate) fn install_podup_shim(shim_dir: &Path, body: &str) {
	let path = write_podup_shim(shim_dir, body);
	let probe = std::process::Command::new("sh")
		.arg("-n")
		.arg(&path)
		.status()
		.expect("sh -n probe");
	assert!(
		probe.success(),
		"shim at {} has a shell syntax error; body:\n{body}",
		path.display()
	);
}

/// A `mail.toml` whose `data_dir` points at `data_dir`. The
/// compose file is created explicitly by the test when the case
/// needs it, so the "missing compose" test can omit it.
#[allow(dead_code)]
pub(crate) fn write_config(data_dir: &Path) -> PathBuf {
	let body = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n",
		data_dir
	);
	let cfg_path = data_dir.parent().unwrap().join("mail.toml");
	std::fs::write(&cfg_path, body).expect("write config");
	#[cfg(unix)]
	{
		// Config::load rejects group/world-readable files; the
		// default 0o644 from a `std::fs::write` would trip that
		// gate and the test would observe a different exit.
		std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o600))
			.expect("chmod 0600 on config");
	}
	cfg_path
}

/// Spawn the real `epistle` binary with the stub `podup` first on
/// `PATH` and capture both streams. The stub's first line is
/// `sh -n`-probed, so a syntax error in the shim body turns this
/// spawn into a clear test panic before the binary ever runs.
#[allow(dead_code)]
pub(crate) fn run_with_podup(args: &[&str], shim_dir: &Path) -> std::process::Output {
	let mut cmd = Command::new(binary());
	cmd.args(args);
	cmd.env("PATH", path_with_shim_first(shim_dir));
	cmd.env("XDG_RUNTIME_DIR", fake_podman_runtime(shim_dir));
	cmd.env_remove("CLICOLOR_FORCE");
	cmd.env("NO_COLOR", "1");
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	cmd.output().expect("spawn epistle")
}

/// One row in the argv log the stub writes. Each test reads the
/// file back to pin the exact argv podup received.
#[allow(dead_code)]
pub(crate) fn read_argv_log(path: &Path) -> Vec<String> {
	let raw = std::fs::read_to_string(path).expect("read argv log");
	raw.lines()
		.filter(|line| !line.is_empty())
		.map(str::to_owned)
		.collect()
}

/// A podup shim that records its argv and prints the canned JSON
/// the tests pin (one row with an empty `Health`, two publishers,
/// and an unknown extra field the parser must ignore). The canned
/// stdout lives in a sibling file (`ps_canned.json`) that the
/// shim `cat`s, that sidesteps the shell-escaping minefield
/// that comes with stuffing JSON inline into a `printf '%s' …`
/// format string.
#[allow(dead_code)]
pub(crate) fn ps_shim(argv_log: &Path, canned_path: &Path) -> String {
	format!(
		"#!/bin/sh\n\
		 printf '%s\\n' \"$@\" >> {argv_log}\n\
		 if [ \"$1\" = \"--version\" ]; then\n\
		 \tprintf '\\npodup version v5.10.13\\n\\n'\n\
		 \texit 0\n\
		 fi\n\
		 for arg in \"$@\"; do\n\
		 \tif [ \"$arg\" = \"ps\" ]; then\n\
		 \t\tcat {canned}\n\
		 \t\texit 0\n\
		 \tfi\n\
		 done\n\
		 exit 0\n",
		argv_log = argv_log.display(),
		canned = canned_path.display()
	)
}

/// The canned JSON the `ps` shim prints. Includes a row whose
/// `Health` is the empty string, two `Publishers` entries, and an
/// unknown extra field the parser must ignore. The table and
/// `--json` paths both run on these bytes, so a regression in
/// either path is one fixture change away.
#[allow(dead_code)]
pub(crate) const PS_FIXTURE: &str = r#"[
  {
    "Service": "mail",
    "Name": "epistle-mail-1",
    "State": "running",
    "Health": "",
    "ExitCode": 0,
    "Image": "localhost/epistle:latest",
    "Publishers": [
      {
        "URL": "0.0.0.0",
        "TargetPort": 25,
        "PublishedPort": 25,
        "Protocol": "tcp"
      },
      {
        "URL": "0.0.0.0",
        "TargetPort": 587,
        "PublishedPort": 587,
        "Protocol": "tcp"
      }
    ],
    "ExtraFutureField": "ignored by epistle"
  }
]
"#;

/// Write `PS_FIXTURE` to a sibling file in the same temp dir the
/// shim lives in. `ps_shim` references the path, so the JSON is
/// `cat`ed verbatim, no shell metacharacters in scope.
#[allow(dead_code)]
pub(crate) fn write_ps_fixture(dir: &Path) -> PathBuf {
	let path = dir.join("ps_canned.json");
	std::fs::write(&path, PS_FIXTURE).expect("write ps fixture");
	path
}

/// A podup shim that only records argv, prints the canonical
/// `v5.10.13` banner, and exits 0 for every other command. Used
/// by the streaming subcommand tests (`up`, `down`, `logs`,
/// `restart`).
#[allow(dead_code)]
pub(crate) fn recorder_shim(argv_log: &Path) -> String {
	format!(
		"#!/bin/sh\n\
		 printf '%s\\n' \"$@\" >> {argv_log}\n\
		 if [ \"$1\" = \"--version\" ]; then\n\
		 \tprintf '\\npodup version v5.10.13\\n\\n'\n\
		 \texit 0\n\
		 fi\n\
		 exit 0\n",
		argv_log = argv_log.display()
	)
}

/// Run a streaming subcommand (`up`, `down`, `logs`, `restart`)
/// with the recorder shim. Returns the captured output and the
/// argv podup received.
#[allow(dead_code)]
pub(crate) fn run_streaming(
	args: &[&str],
	shim_dir: &Path,
	argv_log: &Path,
) -> (std::process::Output, Vec<String>) {
	let output = run_with_podup(args, shim_dir);
	let argv = read_argv_log(argv_log);
	(output, argv)
}

/// Build the `data_dir` and the compose file
/// `<data_dir>/compose/compose.yaml`. Returns the data dir so the
/// test can place its own `mail.toml` next to it.
#[allow(dead_code)]
pub(crate) fn data_dir_with_compose(parent: &Path) -> PathBuf {
	let data_dir = parent.join("data");
	let compose = data_dir.join("compose/compose.yaml");
	std::fs::create_dir_all(compose.parent().unwrap()).expect("mkdir compose");
	std::fs::write(&compose, b"# empty compose fixture for stack tests\n").expect("write compose");
	data_dir
}

/// The presence check needs no live socket in podup-only fixtures.
#[allow(dead_code)]
pub(crate) fn fake_podman_runtime(parent: &Path) -> PathBuf {
	let runtime = parent.join("runtime");
	std::fs::create_dir_all(runtime.join("podman")).expect("create runtime fixture");
	std::fs::write(runtime.join("podman/podman.sock"), b"").expect("write socket marker");
	runtime
}
