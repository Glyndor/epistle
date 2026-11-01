//! Harness for the postinst steps that depend on something finishing a moment
//! later: stubs that fail the first times they are called, and a `sleep` that
//! returns at once and can make the host "become ready" while it is waited on.

use super::{read, stubs::write_stub};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A stub that appends its arguments to `<name>.log`, fails its first
/// `failures` calls with a message on stderr, and then runs `on_success`.
pub(super) fn flaky(name: &str, failures: u32, on_success: &str) -> String {
	format!(
		"n=$(cat \"$STUB_STATE/{name}.count\" 2>/dev/null || echo 0)\n\
		 n=$((n + 1))\n\
		 echo \"$n\" > \"$STUB_STATE/{name}.count\"\n\
		 printf '%s\\n' \"$*\" >> \"$STUB_STATE/{name}.log\"\n\
		 if [ \"$n\" -le {failures} ]; then echo \"{name}: simulated failure $n\" >&2; exit 1; fi\n\
		 {on_success}"
	)
}

/// What a run starts from.
pub(super) struct Setup {
	/// Stubs by name; a later entry replaces an earlier one.
	pub(super) stubs: Vec<(&'static str, String)>,
	/// Whether `/run/systemd/system` exists.
	pub(super) systemd: bool,
	/// Whether the account's runtime directory exists at the start.
	pub(super) runtime: bool,
	/// Whether the account's tables already hold its block.
	pub(super) ranges: bool,
	/// Whether the state directories exist.
	pub(super) state: bool,
	/// Whether the stack was enabled by a previous `epistle init`.
	pub(super) unit: bool,
}

impl Default for Setup {
	fn default() -> Self {
		Self {
			stubs: Vec::new(),
			systemd: false,
			runtime: true,
			ranges: true,
			state: true,
			unit: false,
		}
	}
}

/// One temporary root the postinst can be run against more than once.
pub(super) struct Host {
	dir: tempfile::TempDir,
}

/// The outcome of one run.
pub(super) struct Run {
	pub(super) code: Option<i32>,
	pub(super) stderr: String,
}

impl Host {
	pub(super) fn new(setup: Setup) -> Self {
		let dir = tempfile::tempdir().unwrap();
		let root = dir.path();
		for path in ["bin", "stub-state", "config", "rollback"] {
			std::fs::create_dir_all(root.join(path)).unwrap();
		}
		if setup.state {
			std::fs::create_dir_all(root.join("state/data")).unwrap();
		}
		if setup.systemd {
			std::fs::create_dir_all(root.join("run/systemd/system")).unwrap();
		}
		if setup.runtime {
			std::fs::create_dir_all(root.join("run/user/103")).unwrap();
		}
		if setup.unit {
			let units = root.join("state/.config/systemd/user");
			std::fs::create_dir_all(&units).unwrap();
			std::fs::write(units.join("podup-epistle.service"), "").unwrap();
		}
		if setup.ranges {
			for table in ["subuid", "subgid"] {
				std::fs::write(
					root.join(table),
					"tester:100000:65536\nglyndor-epistle:165536:65536\n",
				)
				.unwrap();
			}
		}
		let mut stubs: Vec<(&'static str, String)> = vec![
			("getent", "exit 0".into()),
			("id", "echo 103".into()),
			("loginctl", "exit 0".into()),
			(
				"runuser",
				"printf '%s\\n' \"$*\" >> \"$STUB_STATE/runuser.log\"".into(),
			),
			("podman", "exit 0".into()),
			("adduser", "exit 0".into()),
			("install", "exit 0".into()),
			("usermod", "exit 0".into()),
			("sleep", "echo \"$*\" >> \"$STUB_STATE/sleep.log\"".into()),
		];
		stubs.extend(setup.stubs);
		for (name, body) in stubs {
			write_stub(&root.join("bin").join(name), &body);
		}
		Self { dir }
	}

	pub(super) fn root(&self) -> &Path {
		self.dir.path()
	}

	fn state(&self) -> PathBuf {
		self.root().join("stub-state")
	}

	/// Lines logged by the stub `name`, one per call.
	pub(super) fn calls(&self, name: &str) -> Vec<String> {
		std::fs::read_to_string(self.state().join(format!("{name}.log")))
			.unwrap_or_default()
			.lines()
			.map(str::to_string)
			.collect()
	}

	/// How many times `sleep` was called.
	pub(super) fn sleeps(&self) -> usize {
		self.calls("sleep").len()
	}

	/// Run `postinst configure <previous>` (a fresh install when `previous` is
	/// `None`) against this root.
	pub(super) fn configure(&self, previous: Option<&str>) -> Run {
		let root = self.root();
		let mut script = read("debian/epistle.postinst");
		let systemd = if root.join("run/systemd/system").is_dir() {
			"run/systemd/system"
		} else {
			"no-systemd"
		};
		for (from, to) in [
			("/etc/subuid", "subuid"),
			("/etc/subgid", "subgid"),
			("/etc/login.defs", "login.defs"),
			("/var/lib/glyndor/epistle", "state"),
			("/var/lib/epistle-rollback", "rollback"),
			("/etc/epistle", "config"),
			("/run/systemd/system", systemd),
			("/run/user", "run/user"),
			("/proc/sys", "missing-sys"),
		] {
			script = script.replace(from, root.join(to).to_str().unwrap());
		}
		let script_path = root.join("postinst");
		std::fs::write(&script_path, script).unwrap();
		let mut command = Command::new("timeout");
		command
			.args(["--kill-after=1", "20", "sh"])
			.arg(&script_path)
			.arg("configure");
		if let Some(previous) = previous {
			command.arg(previous);
		}
		let output = command
			.env(
				"PATH",
				format!("{}:/usr/bin:/bin", root.join("bin").display()),
			)
			.env("STUB_STATE", self.state())
			.env("HOST_ROOT", root)
			.output()
			.unwrap();
		Run {
			code: output.status.code(),
			stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
		}
	}
}
