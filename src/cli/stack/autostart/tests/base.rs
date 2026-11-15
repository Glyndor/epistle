//! `ensure` against a fake host that records every call it gets.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::*;

/// A host with a unit file and systemd answers, recording what is asked and
/// what is installed. `install` writes the unit the way podup does.
struct Fake {
	unit: Option<String>,
	loaded: bool,
	enabled: bool,
	fail_install: bool,
	asked: Vec<String>,
	installs: usize,
	files: Vec<PathBuf>,
	answers: BTreeMap<&'static str, String>,
}

fn unit_for(files: &[&str]) -> String {
	let args: Vec<String> = files.iter().map(|file| format!("-f {file}")).collect();
	format!(
		"[Service]\nExecStart=/usr/bin/podup {} -p epistle up -d --no-build --pull never\n",
		args.join(" ")
	)
}

impl Fake {
	fn state(unit: Option<&str>, loaded: bool, enabled: bool) -> Self {
		Fake {
			unit: unit.map(str::to_string),
			loaded,
			enabled,
			fail_install: false,
			asked: Vec::new(),
			installs: 0,
			files: vec![PathBuf::from("/c/compose.yaml")],
			answers: BTreeMap::new(),
		}
	}
}

impl Host for Fake {
	fn unit_path(&self) -> PathBuf {
		PathBuf::from("/home/u/.config/systemd/user/podup-epistle.service")
	}
	fn read(&mut self, _: &Path) -> Result<Option<String>, String> {
		Ok(self.unit.clone())
	}
	fn systemctl(&mut self, args: &[&str]) -> Result<String, String> {
		self.asked.push(args.join(" "));
		let _ = &self.answers;
		Ok(match args {
			["show", ..] if self.loaded => "LoadState=loaded".to_string(),
			["show", ..] => "LoadState=not-found".to_string(),
			["is-enabled", ..] if self.enabled => "enabled".to_string(),
			_ => "disabled".to_string(),
		})
	}
	fn install(&mut self) -> Result<(), String> {
		self.installs += 1;
		if self.fail_install {
			return Err("`podup autostart install` failed".to_string());
		}
		self.unit = Some(unit_for(
			&self
				.files
				.iter()
				.map(|file| file.to_str().unwrap())
				.collect::<Vec<_>>(),
		));
		self.loaded = true;
		self.enabled = true;
		Ok(())
	}
}

fn current() -> Vec<PathBuf> {
	vec![PathBuf::from("/c/compose.yaml")]
}

#[test]
fn a_unit_that_is_installed_loaded_enabled_and_current_runs_nothing() {
	let mut host = Fake::state(Some(&unit_for(&["/c/compose.yaml"])), true, true);
	assert_eq!(ensure(&mut host, &current()), Ok(Outcome::Unchanged));
	assert_eq!(host.installs, 0);
}

#[test]
fn a_missing_unit_is_installed() {
	let mut host = Fake::state(None, false, false);
	assert_eq!(
		ensure(&mut host, &current()),
		Ok(Outcome::Installed(Reason::Missing))
	);
	assert_eq!(host.installs, 1);
}

#[test]
fn a_disabled_unit_is_installed_again() {
	let mut host = Fake::state(Some(&unit_for(&["/c/compose.yaml"])), true, false);
	assert_eq!(
		ensure(&mut host, &current()),
		Ok(Outcome::Installed(Reason::Disabled))
	);
	assert_eq!(host.installs, 1);
}

#[test]
fn a_unit_systemd_has_not_loaded_is_installed_again() {
	let mut host = Fake::state(Some(&unit_for(&["/c/compose.yaml"])), false, true);
	assert_eq!(
		ensure(&mut host, &current()),
		Ok(Outcome::Installed(Reason::NotLoaded))
	);
}

#[test]
fn a_unit_with_another_file_list_is_installed_again() {
	for stale in [
		unit_for(&["/c/compose.yaml", "/c/compose.override.yaml"]),
		unit_for(&["/gone/compose.yaml"]),
		"[Service]\nType=oneshot\n".to_string(),
	] {
		let mut host = Fake::state(Some(&stale), true, true);
		assert_eq!(
			ensure(&mut host, &current()),
			Ok(Outcome::Installed(Reason::Stale)),
			"{stale}"
		);
	}
}

#[test]
fn running_it_twice_installs_once() {
	let mut host = Fake::state(None, false, false);
	assert!(matches!(
		ensure(&mut host, &current()),
		Ok(Outcome::Installed(_))
	));
	let asked = host.asked.len();
	assert_eq!(ensure(&mut host, &current()), Ok(Outcome::Unchanged));
	assert_eq!(host.installs, 1, "the second run installed again");
	assert!(host.asked.len() > asked, "the second run did not look");
}

#[test]
fn an_install_that_leaves_the_unit_wrong_is_an_error_not_a_success() {
	struct Broken(Fake);
	impl Host for Broken {
		fn unit_path(&self) -> PathBuf {
			self.0.unit_path()
		}
		fn read(&mut self, path: &Path) -> Result<Option<String>, String> {
			self.0.read(path)
		}
		fn systemctl(&mut self, args: &[&str]) -> Result<String, String> {
			self.0.systemctl(args)
		}
		fn install(&mut self) -> Result<(), String> {
			Ok(())
		}
	}
	let mut host = Broken(Fake::state(None, false, false));
	let error = ensure(&mut host, &current()).unwrap_err();
	assert!(error.contains("still"), "{error}");
}

#[test]
fn a_failed_install_is_reported() {
	let mut host = Fake::state(None, false, false);
	host.fail_install = true;
	assert!(ensure(&mut host, &current()).is_err());
}

#[test]
fn the_host_is_only_asked_to_look_and_to_install() {
	// The trait has no way to start, pull, build or stop anything: whatever
	// state the unit is in, the calls are reads and one install.
	for (unit, loaded, enabled) in [
		(None, false, false),
		(Some(unit_for(&["/c/compose.yaml"])), true, false),
		(Some(unit_for(&["/old.yaml"])), true, true),
		(Some(unit_for(&["/c/compose.yaml"])), true, true),
	] {
		let mut host = Fake::state(unit.as_deref(), loaded, enabled);
		let _ = ensure(&mut host, &current());
		assert!(
			host.asked
				.iter()
				.all(|call| call.starts_with("show ") || call.starts_with("is-enabled ")),
			"{:?}",
			host.asked
		);
		assert!(host.installs <= 1);
	}
}
