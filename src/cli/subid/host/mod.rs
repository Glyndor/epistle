//! The real [`Host`]: the tables under `/etc`, `usermod`, and the account's
//! user manager and Podman reached through `runuser`.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::mover::{Host, UNITS};
use super::retry::{self, Failed};
use super::shift::{self, Shift, Tally};
use super::table::{ACCOUNT, Block};

/// The host as `epistle move-subids` sees it when run as root.
pub(super) struct System {
	/// The account's uid, for its runtime directory.
	uid: u32,
	/// The account's home, which holds its Podman storage.
	home: PathBuf,
	/// Every tree whose files may carry ids of the account's block.
	roots: Vec<PathBuf>,
}

impl System {
	/// Look the account up and collect the trees to shift: its home, its
	/// Podman runtime directory, and the storage, volume and data paths when
	/// they lie outside the home.
	pub(super) fn new(config: &Path) -> Result<Self, String> {
		let user = super::super::rootless::lookup_user()
			.map_err(|error| format!("cannot look up {ACCOUNT}: {error}"))?
			.ok_or_else(|| format!("there is no {ACCOUNT} account"))?;
		let mut system = Self {
			uid: user.uid,
			home: user.home,
			roots: Vec::new(),
		};
		system.roots.push(system.home.clone());
		system.roots.push(system.runtime().join("containers"));
		let mut extra = system.storage_paths();
		if let Ok(config) = crate::config::Config::load(config) {
			extra.push(config.data_dir);
		}
		for path in extra {
			if !system.roots.iter().any(|root| path.starts_with(root)) {
				system.roots.push(path);
			}
		}
		Ok(system)
	}

	fn runtime(&self) -> PathBuf {
		PathBuf::from(format!("/run/user/{}", self.uid))
	}

	/// A command run as the account, with the environment its user manager
	/// and rootless Podman expect.
	fn account(&self, program: &str) -> Command {
		let runtime = self.runtime();
		let mut command = Command::new("runuser");
		command
			.args(["-u", ACCOUNT, "--", program])
			.env("HOME", &self.home)
			.env("XDG_RUNTIME_DIR", &runtime)
			.env(
				"DBUS_SESSION_BUS_ADDRESS",
				format!("unix:path={}/bus", runtime.display()),
			)
			.current_dir(&self.home)
			.stdin(Stdio::null());
		command
	}

	/// Whether the account's user manager runs (linger is on).
	fn user_manager(&self) -> bool {
		self.runtime().join("systemd").is_dir()
	}

	/// The storage and volume paths Podman reports, best effort: they
	/// are under the home unless storage.conf moved them.
	fn storage_paths(&self) -> Vec<PathBuf> {
		if !on_path("podman") {
			return Vec::new();
		}
		let output = self
			.account("podman")
			.args([
				"info",
				"--format",
				"{{.Store.GraphRoot}}\n{{.Store.VolumePath}}",
			])
			.stderr(Stdio::null())
			.output();
		match output {
			Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
				.lines()
				.filter(|line| line.starts_with('/'))
				.map(PathBuf::from)
				.collect(),
			_ => Vec::new(),
		}
	}

	/// `systemctl --user <verb>` each unit in turn. One call per unit keeps
	/// the order: given together, systemd runs the jobs in parallel, and the
	/// podup unit's `ExecStop` needs the Podman socket that a stop of
	/// `podman.socket` in the same call could take away first.
	fn systemctl(&self, verb: &str, units: &[String]) -> Result<(), String> {
		if !self.user_manager() {
			return Ok(());
		}
		for unit in units {
			let mut command = self.account("systemctl");
			command.args(["--user", verb, unit]);
			checked(command, &format!("systemctl --user {verb} {unit}"))?;
		}
		Ok(())
	}
}

/// Whether `program` is an executable file in a `PATH` directory.
fn on_path(program: &str) -> bool {
	std::env::var_os("PATH")
		.is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

/// Run `program` as `usermod` with `args` and the account's name. Another
/// tool can hold the lock on the tables for a moment; asking again a little
/// later finds it free. The locale is fixed because the lock is recognised by
/// the words of the English message.
fn usermod_with(program: &str, args: &[String], wait: std::time::Duration) -> Result<(), String> {
	let what = format!("usermod {} {ACCOUNT}", args.join(" "));
	retry::run(retry::ATTEMPTS, wait, || {
		let output = Command::new(program)
			.args(args)
			.arg(ACCOUNT)
			.env("LC_ALL", "C")
			.stdin(Stdio::null())
			.output()
			.map_err(|error| Failed {
				message: format!("cannot run `{what}`: {error}"),
				transient: false,
			})?;
		if output.status.success() {
			return Ok(());
		}
		let stderr = String::from_utf8_lossy(&output.stderr);
		eprint!("{stderr}");
		Err(Failed {
			message: format!("`{what}` exited with {}", output.status),
			transient: retry::is_lock_contention(&stderr),
		})
	})
}

/// Whether the command `probe` builds succeeds within `attempts` tries,
/// `wait` apart.
fn manager_answers(probe: impl Fn() -> Command, attempts: u32, wait: std::time::Duration) -> bool {
	retry::run(attempts, wait, || {
		let mut command = probe();
		command.stdout(Stdio::null()).stderr(Stdio::null());
		match command.status() {
			Ok(status) if status.success() => Ok(()),
			_ => Err(Failed {
				message: String::new(),
				transient: true,
			}),
		}
	})
	.is_ok()
}

/// Run `command` and turn a failure into a message naming `what`.
fn checked(mut command: Command, what: &str) -> Result<(), String> {
	match command.status() {
		Ok(status) if status.success() => Ok(()),
		Ok(status) => Err(format!("`{what}` exited with {status}")),
		Err(error) => Err(format!("cannot run `{what}`: {error}")),
	}
}

/// Read a table; a missing one has no entries.
fn read_table(path: &str) -> Result<String, String> {
	match std::fs::read_to_string(path) {
		Ok(text) => Ok(text),
		Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
		Err(error) => Err(format!("cannot read {path}: {error}")),
	}
}

impl Host for System {
	fn tables(&mut self) -> Result<(String, String), String> {
		Ok((read_table("/etc/subuid")?, read_table("/etc/subgid")?))
	}

	fn usermod(&mut self, args: &[String]) -> Result<(), String> {
		usermod_with("usermod", args, retry::WAIT)
	}

	fn active_units(&mut self) -> Result<Vec<String>, String> {
		if !self.user_manager() {
			return Ok(Vec::new());
		}
		let mut active = Vec::new();
		for unit in UNITS {
			let status = self
				.account("systemctl")
				.args(["--user", "is-active", "--quiet", unit])
				.status()
				.map_err(|error| format!("cannot run systemctl --user is-active: {error}"))?;
			if status.success() {
				active.push(unit.to_string());
			}
		}
		Ok(active)
	}

	fn stop_units(&mut self, units: &[String]) -> Result<(), String> {
		if units.is_empty() {
			return Ok(());
		}
		self.systemctl("stop", units)
	}

	fn start_units(&mut self, units: &[String]) -> Result<(), String> {
		self.systemctl("start", units)
	}

	fn running_containers(&mut self) -> Result<Vec<String>, String> {
		if !on_path("podman") {
			return Ok(Vec::new());
		}
		let output = self
			.account("podman")
			.args(["ps", "--quiet", "--no-trunc"])
			.output()
			.map_err(|error| format!("cannot run podman ps: {error}"))?;
		if !output.status.success() {
			return Err(format!("`podman ps` exited with {}", output.status));
		}
		Ok(String::from_utf8_lossy(&output.stdout)
			.split_whitespace()
			.map(str::to_string)
			.collect())
	}

	fn start_containers(&mut self, ids: &[String]) -> Result<(), String> {
		let mut command = self.account("podman");
		command.arg("start").args(ids);
		checked(command, "podman start")
	}

	fn stop_account(&mut self) -> Result<(), String> {
		let manager = format!("user@{}.service", self.uid);
		let active = Command::new("systemctl")
			.args(["is-active", "--quiet", &manager])
			.status()
			.is_ok_and(|status| status.success());
		if active {
			let mut command = Command::new("systemctl");
			command.args(["stop", &manager]);
			checked(command, &format!("systemctl stop {manager}"))?;
		}
		if self.wait_for_no_processes(PROCESS_WAIT) {
			return Ok(());
		}
		// What outlives the user manager runs outside its cgroup, like a pause
		// process a `runuser podman` started. The stack is down, so end it.
		for (pid, line) in processes_of(self.uid) {
			self.log(&format!("stopping leftover process {line}"));
			// SAFETY: kill only sends a signal; the pid was read from /proc
			// for the service account a moment ago.
			unsafe { libc::kill(pid, libc::SIGTERM) };
		}
		self.wait_for_no_processes(PROCESS_WAIT);
		Ok(())
	}

	fn start_account(&mut self) -> Result<(), String> {
		if !Path::new("/var/lib/systemd/linger").join(ACCOUNT).exists() {
			return Ok(());
		}
		let manager = format!("user@{}.service", self.uid);
		let mut command = Command::new("systemctl");
		command.args(["start", &manager]);
		checked(command, &format!("systemctl start {manager}"))?;
		// The job is done before the manager answers on its bus, and the
		// units are started through that bus next.
		let ready = manager_answers(
			|| {
				let mut probe = self.account("systemctl");
				probe.args(["--user", "show-environment"]);
				probe
			},
			retry::MANAGER_ATTEMPTS,
			retry::WAIT,
		);
		if !ready {
			self.log(&format!(
				"the user manager of {ACCOUNT} did not answer on its bus; starting its units may fail"
			));
		}
		Ok(())
	}

	fn account_processes(&mut self) -> Vec<String> {
		processes_of(self.uid)
			.into_iter()
			.map(|(_, line)| line)
			.collect()
	}

	fn migrate(&mut self) -> Result<(), String> {
		if !on_path("podman") {
			return Ok(());
		}
		let mut command = self.account("podman");
		command.args(["system", "migrate"]);
		checked(command, "podman system migrate")
	}

	fn shift(&mut self, shift: Shift) -> Result<Tally, String> {
		let mut total = Tally::default();
		for root in &self.roots {
			let tally = shift::shift_tree(root, shift)
				.map_err(|error| format!("shifting owners under {}: {error}", root.display()))?;
			total.scanned += tally.scanned;
			total.changed += tally.changed;
		}
		Ok(total)
	}

	fn owned(&mut self, uid: Option<Block>, gid: Option<Block>) -> Result<u64, String> {
		let narrow = |block: Option<Block>| -> Result<Option<(u32, u32)>, String> {
			block
				.map(|block| {
					Ok((
						u32::try_from(block.start).map_err(|_| "id out of range")?,
						u32::try_from(block.count).map_err(|_| "id out of range")?,
					))
				})
				.transpose()
				.map_err(|error: &str| error.to_string())
		};
		let (uid, gid) = (narrow(uid)?, narrow(gid)?);
		let mut total = 0;
		for root in &self.roots {
			total += shift::count_owned(root, uid, gid)
				.map_err(|error| format!("reading owners under {}: {error}", root.display()))?;
		}
		Ok(total)
	}

	fn journal(&mut self) -> Result<Option<String>, String> {
		match std::fs::read_to_string(self.journal_path()) {
			Ok(text) => Ok(Some(text)),
			Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
			Err(error) => Err(format!("cannot read the move journal: {error}")),
		}
	}

	fn set_journal(&mut self, text: Option<&str>) -> Result<(), String> {
		let path = self.journal_path();
		let result = match text {
			Some(text) => write_synced(&path, text),
			None => match std::fs::remove_file(&path) {
				Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
				other => other,
			},
		};
		result.map_err(|error| format!("cannot update {}: {error}", path.display()))
	}

	fn log(&mut self, line: &str) {
		eprintln!("epistle: {line}");
	}
}

impl System {
	fn journal_path(&self) -> PathBuf {
		self.home.join(".subid-move")
	}

	/// Poll until the account has no process, at most `limit`.
	fn wait_for_no_processes(&self, limit: std::time::Duration) -> bool {
		let deadline = std::time::Instant::now() + limit;
		loop {
			if processes_of(self.uid).is_empty() {
				return true;
			}
			if std::time::Instant::now() >= deadline {
				return false;
			}
			std::thread::sleep(std::time::Duration::from_millis(200));
		}
	}
}

/// How long the account's processes get to end after each stop.
const PROCESS_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Every process whose real or effective uid is `uid`, as `(pid, "<pid>
/// <command>")`, read from `/proc`. A process that ends while it is read is
/// skipped.
fn processes_of(uid: u32) -> Vec<(i32, String)> {
	let Ok(entries) = std::fs::read_dir("/proc") else {
		return Vec::new();
	};
	let mut found = Vec::new();
	for entry in entries.flatten() {
		let Some(pid) = entry
			.file_name()
			.to_str()
			.and_then(|name| name.parse::<i32>().ok())
		else {
			continue;
		};
		let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
			continue;
		};
		if !owned_by(&status, uid) {
			continue;
		}
		let command = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
		found.push((pid, format!("{pid} {}", command.trim())));
	}
	found
}

/// Whether a `/proc/<pid>/status` text has `uid` as its real or effective uid.
pub(super) fn owned_by(status: &str, uid: u32) -> bool {
	status
		.lines()
		.find_map(|line| line.strip_prefix("Uid:"))
		.is_some_and(|ids| {
			ids.split_whitespace()
				.take(2)
				.any(|id| id.parse::<u32>() == Ok(uid))
		})
}

/// Write `text` to `path` through a temporary file, synced before the rename,
/// so a crash leaves either the old journal or the new one.
fn write_synced(path: &Path, text: &str) -> io::Result<()> {
	use std::io::Write;
	let partial = path.with_extension("partial");
	let mut file = std::fs::File::create(&partial)?;
	file.write_all(text.as_bytes())?;
	file.sync_all()?;
	std::fs::rename(&partial, path)
}

#[cfg(test)]
mod tests;
