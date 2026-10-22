//! Account identity, system-unit shutdown, retry, and legacy configuration.
use super::{read, stubs::write_stub};
use std::{
	fs,
	os::unix::fs::symlink,
	path::PathBuf,
	process::{Command, Output},
};

struct Host {
	tree: tempfile::TempDir,
	account: String,
	aliases: String,
}

impl Host {
	fn new() -> Self {
		let tree = tempfile::tempdir().unwrap();
		let root = tree.path();
		for path in [
			"bin",
			"state/data",
			"config",
			"legacy",
			"proc/123",
			"systemd",
			"etc",
			"runtime",
		] {
			fs::create_dir_all(root.join(path)).unwrap();
		}
		fs::write(root.join("state/data/mail"), "mail").unwrap();
		fs::write(root.join("config/mail.toml"), "config").unwrap();
		fs::write(root.join("legacy/epistle.toml"), "legacy config").unwrap();
		fs::write(root.join("proc/123/status"), "Uid:\t900\t900\t900\t900\n").unwrap();
		fs::write(root.join("etc/login.defs"), "SYS_UID_MAX 999\n").unwrap();
		for name in ["subuid", "subgid"] {
			fs::write(root.join("etc").join(name), "").unwrap();
		}
		for name in [
			"loginctl",
			"runuser",
			"deluser",
			"usermod",
			"start-stop-daemon",
		] {
			write_stub(
				&root.join("bin").join(name),
				&format!("echo '{name}' \"$*\" >> \"$HOST/calls\""),
			);
		}
		write_stub(
			&root.join("bin/id"),
			"awk -F: '{print $3}' \"$HOST/account\"",
		);
		write_stub(&root.join("bin/stat"), "echo 900");
		write_stub(
			&root.join("bin/getent"),
			"if [ -n \"${2:-}\" ]; then cat \"$HOST/account\"; else cat \"$HOST/accounts\"; fi",
		);
		write_stub(
			&root.join("bin/systemctl"),
			"echo systemctl \"$*\" >> \"$HOST/calls\"\ncase \"$*\" in\n 'stop epistle.service') rm -f \"$HOST/proc/123/status\";;\nesac",
		);
		let account = format!(
			"glyndor-epistle:x:900:900::{}:/usr/sbin/nologin\n",
			root.join("state").display()
		);
		Self {
			tree,
			account,
			aliases: String::new(),
		}
	}

	fn path(&self, path: &str) -> PathBuf {
		self.tree.path().join(path)
	}

	fn run(&self) -> Output {
		fs::write(self.path("account"), &self.account).unwrap();
		fs::write(
			self.path("accounts"),
			format!("{}{}", self.account, self.aliases),
		)
		.unwrap();
		let mut script = read("debian/epistle.postrm");
		for (from, to) in [
			("/var/lib/glyndor/epistle", "state"),
			("/etc/epistle", "config"),
			("/etc/glyndor/epistle", "legacy"),
			("/etc/glyndor", "legacy-parent"),
			("/etc/login.defs", "etc/login.defs"),
			("/etc/subuid", "etc/subuid"),
			("/etc/subgid", "etc/subgid"),
			("/run/systemd/system", "systemd"),
			("/run/user/", "runtime/"),
			("/proc/", "proc/"),
		] {
			script = script.replace(from, self.path(to).to_str().unwrap());
		}
		script = script.replace("EPISTLE_STOP_WAIT=30", "EPISTLE_STOP_WAIT=0");
		Command::new("timeout")
			.args([
				"--kill-after=1",
				"5",
				"sh",
				"-c",
				&script,
				"postrm",
				"purge",
			])
			.env(
				"PATH",
				format!("{}:/usr/bin:/bin", self.path("bin").display()),
			)
			.env("HOST", self.tree.path())
			.output()
			.unwrap()
	}

	fn calls(&self) -> String {
		fs::read_to_string(self.path("calls")).unwrap_or_default()
	}
}

#[test]
fn purge_stops_the_documented_system_service_and_succeeds_on_retry() {
	let host = Host::new();
	for _ in 0..2 {
		let out = host.run();
		assert!(out.status.success(), "purge must stop the writer: {out:?}");
		assert!(
			!host.path("state").exists(),
			"remove data only after stopping the unit"
		);
	}
	let calls = host.calls();
	let stop = calls
		.find("systemctl stop epistle.service")
		.expect("stop the system unit");
	let remove = calls.find("deluser").unwrap();
	assert!(stop < remove, "stop before account removal: {calls}");
}

#[test]
fn purge_rejects_shared_root_regular_and_foreign_accounts_without_termination() {
	for kind in ["shared", "root", "regular", "home", "shell"] {
		let mut host = Host::new();
		fs::remove_file(host.path("proc/123/status")).unwrap();
		match kind {
			"shared" => host.aliases = "other:x:900:900::/home/other:/bin/sh\n".to_owned(),
			"root" => host.account = host.account.replace(":900:", ":0:"),
			"regular" => host.account = host.account.replace(":900:", ":1000:"),
			"home" => host.account = host.account.replace("/state:", "/other:"),
			"shell" => host.account = host.account.replace("/usr/sbin/nologin", "/bin/bash"),
			_ => unreachable!(),
		}
		let out = host.run();
		assert_eq!(
			out.status.code(),
			Some(1),
			"{kind}: refuse unsafe identity: {out:?}"
		);
		assert!(
			String::from_utf8_lossy(&out.stderr).contains("account identity"),
			"{kind}: identify the refusal: {out:?}"
		);
		assert!(
			host.calls().is_empty(),
			"{kind}: no termination or removal: {}",
			host.calls()
		);
		assert!(host.path("state/data/mail").exists());
	}
}

#[test]
fn purge_without_systemd_stops_only_the_validated_account_by_name() {
	let host = Host::new();
	fs::remove_dir(host.path("systemd")).unwrap();
	write_stub(
		&host.path("bin/start-stop-daemon"),
		"echo start-stop-daemon \"$*\" >> \"$HOST/calls\"\nrm -f \"$HOST/proc/123/status\"",
	);
	let out = host.run();
	assert!(out.status.success(), "stop the direct writer: {out:?}");
	assert!(
		host.calls().contains("--user glyndor-epistle"),
		"scope termination by account name: {}",
		host.calls()
	);
	assert!(!host.calls().contains("--user 900"));
}

#[test]
fn purge_removes_only_the_known_legacy_config_and_keeps_other_content() {
	let host = Host::new();
	fs::remove_file(host.path("proc/123/status")).unwrap();
	fs::write(host.path("legacy/unrelated"), "keep").unwrap();
	let out = host.run();
	assert!(out.status.success(), "{out:?}");
	assert!(
		!host.path("legacy/epistle.toml").exists(),
		"remove the earlier documented config"
	);
	assert!(
		host.path("legacy/unrelated").exists(),
		"keep unrelated files"
	);
}

#[test]
fn purge_preserves_legacy_configuration_links() {
	for parent_link in [false, true] {
		let host = Host::new();
		fs::remove_file(host.path("proc/123/status")).unwrap();
		fs::create_dir(host.path("outside")).unwrap();
		fs::write(host.path("outside/epistle.toml"), "keep").unwrap();
		fs::remove_file(host.path("legacy/epistle.toml")).unwrap();
		if parent_link {
			fs::remove_dir(host.path("legacy")).unwrap();
			symlink(host.path("outside"), host.path("legacy")).unwrap();
		} else {
			symlink(
				host.path("outside/epistle.toml"),
				host.path("legacy/epistle.toml"),
			)
			.unwrap();
		}
		let out = host.run();
		assert!(out.status.success(), "{out:?}");
		assert!(host.path("outside/epistle.toml").exists());
		assert!(
			String::from_utf8_lossy(&out.stderr).contains("left in place"),
			"report retained links: {out:?}"
		);
	}
}

#[test]
fn purge_keeps_legacy_configuration_owned_by_another_account() {
	let host = Host::new();
	fs::remove_file(host.path("proc/123/status")).unwrap();
	write_stub(&host.path("bin/stat"), "echo 1001");
	let out = host.run();
	assert!(out.status.success(), "{out:?}");
	assert!(
		host.path("legacy/epistle.toml").exists(),
		"keep foreign-owned configuration"
	);
	assert!(
		String::from_utf8_lossy(&out.stderr).contains("left in place"),
		"report retained configuration: {out:?}"
	);
}

#[test]
fn purge_preserves_data_if_the_system_service_cannot_be_stopped_then_retries() {
	let host = Host::new();
	fs::remove_file(host.path("proc/123/status")).unwrap();
	write_stub(
		&host.path("bin/systemctl"),
		"case \"$*\" in 'stop epistle.service') exit 1;; *LoadState*) echo loaded;; esac",
	);
	let out = host.run();
	assert_eq!(
		out.status.code(),
		Some(1),
		"a failed unit stop must preserve data: {out:?}"
	);
	assert!(host.path("state/data/mail").exists());
	assert!(!host.calls().contains("deluser"));
	write_stub(&host.path("bin/systemctl"), "exit 0");
	assert!(host.run().status.success(), "retry after the stop succeeds");
}

#[test]
fn purge_retry_after_account_removal_does_not_orphan_legacy_configuration() {
	let host = Host::new();
	write_stub(
		&host.path("bin/rm"),
		"if [ \"$*\" = \"-rf $HOST/config\" ] && [ ! -e \"$HOST/rm-failed\" ]; then touch \"$HOST/rm-failed\"; exit 1; fi\nexec /bin/rm \"$@\"",
	);
	assert_eq!(
		host.run().status.code(),
		Some(1),
		"simulate cleanup failure after account removal"
	);
	assert!(
		host.calls().contains("deluser"),
		"the account was already removed"
	);
	write_stub(&host.path("bin/id"), "exit 1");
	let retry = host.run();
	assert!(
		retry.status.success(),
		"the cleanup retry must complete: {retry:?}"
	);
	assert!(
		!host.path("legacy/epistle.toml").exists(),
		"do not lose the validated legacy owner across a retry"
	);
}
