//! The `boot` items against a fake host in a good and a bad state.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::host::{Account, Link};
use super::*;
use crate::cli::stack::autostart::{Host, dropins};

pub(super) const UNIT_PATH: &str = "/home/u/.config/systemd/user/podup-epistle.service";
pub(super) const COMPOSE: &str = "/data/compose/compose.yaml";

/// A host that answers from tables and records every question.
pub(super) struct Fake {
	pub(super) files: BTreeMap<PathBuf, String>,
	pub(super) user: BTreeMap<String, String>,
	pub(super) system: BTreeMap<String, String>,
	pub(super) present: BTreeSet<PathBuf>,
	pub(super) images: BTreeSet<String>,
	pub(super) boot_sysctl: Result<String, String>,
	pub(super) asked: Vec<String>,
	pub(super) pulled: Vec<String>,
	pub(super) version: Option<u32>,
	pub(super) ps: Result<String, String>,
	pub(super) log: String,
	pub(super) links: BTreeMap<IpAddr, Link>,
}

pub(super) fn unit_text() -> String {
	"[Unit]\nWants=podman-user-wait-network-online.service\nAfter=podman-user-wait-network-online.service\n[Service]\nExecStart=/usr/bin/podup -f /data/compose/compose.yaml -p epistle up -d --no-build --pull never\n".to_string()
}

pub(super) fn compose_text() -> String {
	serde_json::json!({"services": {
		"mail": {"image": "ghcr.io/glyndor/epistle:1", "restart": "unless-stopped"},
		"db": {"image": "postgres:18", "restart": "unless-stopped"},
	}})
	.to_string()
}

/// A host where everything the boot needs is in place.
pub(super) fn good() -> Fake {
	let mut files = BTreeMap::new();
	files.insert(PathBuf::from(UNIT_PATH), unit_text());
	files.insert(PathBuf::from(COMPOSE), compose_text());
	files.insert(
		PathBuf::from("/proc/sys/net/ipv4/ip_unprivileged_port_start"),
		"25\n".into(),
	);
	files.insert(
		PathBuf::from("/etc/fstab"),
		"UUID=1 / ext4 defaults 0 1\n".into(),
	);
	files.insert(
		PathBuf::from("/proc/self/mountinfo"),
		"1 0 8:1 / / rw - ext4 /dev/sda1 rw\n".into(),
	);
	files.insert(
		PathBuf::from("/home/u/.config/systemd/user/podup-epistle.service.d/10-epistle.conf"),
		dropins::user_text(),
	);
	files.insert(
		dropins::system_path(1001),
		dropins::system_text(None).unwrap(),
	);
	let mut user = BTreeMap::new();
	for (query, answer) in [
		("is-enabled podup-epistle.service", "enabled"),
		(
			"show podup-epistle.service -p ActiveState -p Result",
			"ActiveState=active\nResult=success",
		),
		(
			"show podup-epistle.service -p LoadState",
			"LoadState=loaded",
		),
		("is-enabled podman.socket", "enabled"),
		("is-active podman.socket", "active"),
		(
			"show podman-user-wait-network-online.service -p LoadState",
			"LoadState=loaded",
		),
	] {
		user.insert(query.to_string(), answer.to_string());
	}
	let mut system = BTreeMap::new();
	system.insert(
		"is-active user@1001.service".to_string(),
		"active".to_string(),
	);
	system.insert(
		"is-active network-online.target".to_string(),
		"active".to_string(),
	);
	let present = [
		"/var/lib/systemd/linger/glyndor-epistle",
		"/run/user/1001",
		"/data",
		"/home/u/.local/share/containers",
	]
	.iter()
	.map(PathBuf::from)
	.collect();
	Fake {
		files,
		user,
		system,
		present,
		images: ["ghcr.io/glyndor/epistle:1", "postgres:18"].iter().map(|s| s.to_string()).collect(),
		boot_sysctl: Ok("# /usr/lib/sysctl.d/30-glyndor-epistle.conf\nnet.ipv4.ip_unprivileged_port_start = 25\n".into()),
		asked: Vec::new(),
		pulled: Vec::new(),
		version: Some(255),
		ps: Ok(r#"[{"Service":"mail","State":"running","ExitCode":0},{"Service":"db","State":"running","ExitCode":0}]"#.into()),
		log: String::new(),
		links: BTreeMap::new(),
	}
}

impl Host for Fake {
	fn unit_path(&self) -> PathBuf {
		PathBuf::from(UNIT_PATH)
	}
	fn read(&mut self, path: &Path) -> Result<Option<String>, String> {
		Ok(self.files.get(path).cloned())
	}
	fn systemctl(&mut self, args: &[&str]) -> Result<String, String> {
		let key = args.join(" ");
		self.asked.push(format!("user {key}"));
		Ok(self.user.get(&key).cloned().unwrap_or_default())
	}
	fn install(&mut self) -> Result<(), String> {
		panic!("a boot check must never install anything");
	}
}

impl BootHost for Fake {
	fn account(&self) -> Account {
		Account {
			name: "glyndor-epistle".into(),
			uid: 1001,
		}
	}
	fn exists(&mut self, path: &Path) -> bool {
		self.present.contains(path)
	}
	fn system_systemctl(&mut self, args: &[&str]) -> Result<String, String> {
		let key = args.join(" ");
		self.asked.push(format!("system {key}"));
		Ok(self.system.get(&key).cloned().unwrap_or_default())
	}
	fn sysctl_at_boot(&mut self) -> Result<String, String> {
		self.boot_sysctl.clone()
	}
	fn image_exists(&mut self, image: &str) -> Result<bool, String> {
		self.asked.push(format!("image exists {image}"));
		Ok(self.images.contains(image))
	}
	fn storage_dir(&self) -> PathBuf {
		PathBuf::from("/home/u/.local/share/containers")
	}
	fn systemd_version(&mut self) -> Option<u32> {
		self.version
	}
	fn ps_json(&mut self, _: &Path) -> Result<String, String> {
		self.ps.clone()
	}
	fn unit_log(&mut self) -> Result<String, String> {
		Ok(self.log.clone())
	}
	fn link_of(&mut self, ip: IpAddr) -> Link {
		self.links.get(&ip).cloned().unwrap_or(Link::Absent)
	}
}

pub(super) fn config() -> Config {
	Config::parse_text(
		"hostname = \"mail.example.org\"\ndata_dir = \"/data\"\ndomains = [\"example.org\"]\n\n[[listeners]]\nkind = \"smtp\"\naddr = \"0.0.0.0\"\nport = 25\n",
		Path::new("/etc/epistle/mail.toml"),
	)
	.expect("config")
}

pub(super) fn item<'a>(report: &'a AreaReport, name: &str) -> &'a Item {
	report
		.items
		.iter()
		.find(|item| item.name == name)
		.unwrap_or_else(|| panic!("no {name} item in {report:?}"))
}

pub(super) fn run(host: &mut Fake) -> AreaReport {
	check_with(host, &config())
}

#[test]
fn a_host_where_everything_is_in_place_is_ok_on_all_fourteen_items() {
	let mut host = good();
	let report = run(&mut host);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert_eq!(report.items.len(), 14, "{report:?}");
	assert!(
		report.items.iter().all(|item| item.status == Level::Ok),
		"{report:?}"
	);
	assert_eq!(report.detail, "the stack comes back after a reboot");
}

#[test]
fn the_checks_only_read_they_never_install_start_or_pull() {
	let mut host = good();
	host.user.clear();
	host.files.remove(Path::new(UNIT_PATH));
	host.images.clear();
	let _ = run(&mut host);
	for call in &host.asked {
		let verb = call.split_whitespace().nth(1).unwrap_or_default();
		assert!(
			matches!(verb, "is-enabled" | "is-active" | "show" | "exists"),
			"a check asked for {call:?}"
		);
	}
	assert!(host.pulled.is_empty());
}

#[test]
fn no_compose_file_means_no_stack_and_no_items() {
	let mut host = good();
	host.files.remove(Path::new(COMPOSE));
	let report = run(&mut host);
	assert_eq!(report.status, Level::Ok);
	assert!(report.items.is_empty());
}

pub(super) fn assert_bad(host: &mut Fake, name: &str, level: Level, fix: &str) {
	let report = run(host);
	let found = item(&report, name);
	assert_eq!(found.status, level, "{name}: {found:?}");
	assert!(
		found.detail.contains(fix),
		"{name} should say {fix:?}: {found:?}"
	);
	for other in report.items.iter().filter(|other| other.name != name) {
		assert_eq!(
			other.status,
			Level::Ok,
			"{name} broke {}: {other:?}",
			other.name
		);
	}
}

#[test]
fn item_1_linger_off_fails_with_the_enable_command() {
	let mut host = good();
	host.present
		.remove(Path::new("/var/lib/systemd/linger/glyndor-epistle"));
	assert_bad(
		&mut host,
		"linger",
		Level::Fail,
		"sudo loginctl enable-linger glyndor-epistle",
	);
}

#[test]
fn item_2_a_user_manager_that_is_down_or_a_missing_runtime_dir_fails() {
	let mut host = good();
	host.system
		.insert("is-active user@1001.service".into(), "inactive".into());
	assert_bad(
		&mut host,
		"user manager",
		Level::Fail,
		"sudo systemctl start user@1001.service",
	);
	let mut host = good();
	host.present.remove(Path::new("/run/user/1001"));
	assert_bad(&mut host, "user manager", Level::Fail, "/run/user/1001");
}

#[test]
fn item_3_a_missing_unit_fails_and_names_the_repair_that_does_not_recreate() {
	let mut host = good();
	host.files.remove(Path::new(UNIT_PATH));
	let report = run(&mut host);
	let found = item(&report, "boot unit");
	assert_eq!(found.status, Level::Fail);
	assert!(
		found.detail.contains("sudo epistle stack start"),
		"{found:?}"
	);
	assert!(found.detail.contains("without recreating"), "{found:?}");
}

#[test]
fn item_3_a_disabled_unit_fails() {
	let mut host = good();
	host.user
		.insert("is-enabled podup-epistle.service".into(), "disabled".into());
	let report = run(&mut host);
	assert_eq!(item(&report, "boot unit").status, Level::Fail);
	assert!(item(&report, "boot unit").detail.contains("disabled"));
}

#[test]
fn item_3_a_failed_last_result_fails_with_the_journal_command() {
	let mut host = good();
	host.user.insert(
		"show podup-epistle.service -p ActiveState -p Result".into(),
		"ActiveState=failed\nResult=exit-code".into(),
	);
	let report = run(&mut host);
	let found = item(&report, "boot unit");
	assert_eq!(found.status, Level::Fail);
	assert!(found.detail.contains("exit-code"), "{found:?}");
	assert!(
		found
			.detail
			.contains("journalctl _UID=1001 --user-unit=podup-epistle.service")
	);
}

#[test]
fn item_4_a_unit_with_other_files_than_the_stack_fails() {
	let mut host = good();
	host.files.insert(
		PathBuf::from(UNIT_PATH),
		unit_text().replace("/data/compose/compose.yaml", "/old/compose.yaml"),
	);
	let report = run(&mut host);
	let found = item(&report, "unit files");
	assert_eq!(found.status, Level::Fail);
	assert!(
		found.detail.contains("/old/compose.yaml") && found.detail.contains(COMPOSE),
		"{found:?}"
	);
	assert!(found.detail.contains("sudo epistle stack start"));
}

#[test]
fn item_4_an_override_file_the_unit_does_not_list_fails() {
	let mut host = good();
	host.present
		.insert(PathBuf::from("/data/compose/compose.override.yaml"));
	let report = run(&mut host);
	assert_eq!(item(&report, "unit files").status, Level::Fail);
}

#[test]
fn item_5_a_podman_socket_that_is_not_enabled_or_not_active_fails() {
	let mut host = good();
	host.user
		.insert("is-enabled podman.socket".into(), "disabled".into());
	assert_bad(
		&mut host,
		"podman socket",
		Level::Fail,
		"systemctl --user enable --now podman.socket",
	);
	let mut host = good();
	host.user
		.insert("is-active podman.socket".into(), "inactive".into());
	assert_bad(
		&mut host,
		"podman socket",
		Level::Fail,
		"XDG_RUNTIME_DIR=/run/user/1001",
	);
}

#[test]
fn item_6_a_service_with_restart_no_or_none_warns() {
	for restart in [serde_json::json!("no"), serde_json::Value::Null] {
		let mut host = good();
		let mut doc: serde_json::Value = serde_json::from_str(&compose_text()).unwrap();
		doc["services"]["db"]["restart"] = restart;
		host.files.insert(PathBuf::from(COMPOSE), doc.to_string());
		assert_bad(&mut host, "restart policy", Level::Warn, "db");
	}
}

#[test]
fn item_7_a_unit_that_does_not_wait_or_a_shim_systemd_cannot_load_warns() {
	let mut host = good();
	host.files.insert(
		PathBuf::from(UNIT_PATH),
		unit_text().replace("After=", "Before="),
	);
	assert_bad(
		&mut host,
		"network wait",
		Level::Warn,
		"does not wait for the network",
	);
	let mut host = good();
	host.user.insert(
		"show podman-user-wait-network-online.service -p LoadState".into(),
		"LoadState=not-found".into(),
	);
	assert_bad(&mut host, "network wait", Level::Warn, "Podman 5.3.0");
	let mut host = good();
	host.system
		.insert("is-active network-online.target".into(), "inactive".into());
	assert_bad(&mut host, "network wait", Level::Warn, "wait-online");
}
