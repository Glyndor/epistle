//! The boot unit after every path that leaves the stack running, driving the
//! real binary against a podup shim that records each call and writes the
//! unit the way `podup autostart install` does, and a `systemctl` shim that
//! answers from files. `stack down` and `stack stop` must leave it alone, and
//! no path may ask podup for anything that touches a container.

#![cfg(unix)]

#[path = "stack_podup_helpers.rs"]
mod helpers;

use std::path::{Path, PathBuf};

use helpers::{
	data_dir_with_compose, executable, install_podup_shim, run_with_podup, write_config,
};

/// One scenario: the podup and systemctl shims, the data dir and the config.
struct World {
	_dir: tempfile::TempDir,
	shim: PathBuf,
	log: PathBuf,
	state: PathBuf,
	unit: PathBuf,
	compose: PathBuf,
	cfg: PathBuf,
}

impl World {
	fn new() -> Self {
		let dir = tempfile::tempdir().expect("tempdir");
		let shim = dir.path().join("bin");
		let log = dir.path().join("argv.log");
		let state = dir.path().join("state");
		std::fs::create_dir_all(&state).unwrap();
		install_podup_shim(&shim, &podup_body(&log, &state, &shim));
		executable::write_executable(&shim.join("systemctl"), systemctl_body(&state));
		let data = data_dir_with_compose(dir.path());
		let compose = data.join("compose/compose.yaml");
		let cfg = write_config(&data);
		let unit = shim.join("xdg/systemd/user/podup-epistle.service");
		World {
			_dir: dir,
			shim,
			log,
			state,
			unit,
			compose,
			cfg,
		}
	}

	fn run(&self, args: &[&str]) -> std::process::Output {
		let mut full = vec!["stack", "--config", self.cfg.to_str().unwrap()];
		full.extend(args);
		std::fs::write(&self.log, "").unwrap();
		run_with_podup(&full, &self.shim)
	}

	/// Every podup call after `--version`, one line each, as `-f ... verb ...`.
	fn calls(&self) -> Vec<String> {
		std::fs::read_to_string(&self.log)
			.unwrap()
			.lines()
			.filter(|line| *line != "--version")
			.map(str::to_string)
			.collect()
	}

	/// The calls with the `-f <file>` prefix removed.
	fn verbs(&self) -> Vec<String> {
		let prefix = format!("-f {} ", self.compose.display());
		self.calls()
			.iter()
			.map(|call| call.strip_prefix(&prefix).unwrap_or(call).to_string())
			.collect()
	}

	fn installed(&self) -> bool {
		self.unit.exists()
	}

	/// Put a unit that is installed, loaded, enabled and current in place.
	fn fine(&self) {
		write_unit(&self.unit, &format!("-f {}", self.compose.display()));
		std::fs::write(self.state.join("loaded"), "").unwrap();
		std::fs::write(self.state.join("enabled"), "").unwrap();
	}
}

fn write_unit(path: &Path, files: &str) {
	std::fs::create_dir_all(path.parent().unwrap()).unwrap();
	std::fs::write(
		path,
		format!(
			"[Service]\nExecStart=/usr/bin/podup {files} -p epistle up -d --no-build --pull never\n"
		),
	)
	.unwrap();
}

/// podup: logs each call on one line; `autostart install` writes the unit
/// with the files it was given and marks it loaded, and enabled unless it got
/// `--no-start`; `autostart uninstall` removes it.
fn podup_body(log: &Path, state: &Path, shim: &Path) -> String {
	format!(
		"#!/bin/sh\n\
		 printf '%s\\n' \"$*\" >> {log}\n\
		 case \"$*\" in\n\
		 \t--version) printf '\\npodup version v5.19.0\\n\\n' ;;\n\
		 \t*autostart\\ install*)\n\
		 \t\tfiles=''; prev=''\n\
		 \t\tfor a in \"$@\"; do if [ \"$prev\" = '-f' ]; then files=\"$files -f $a\"; fi; prev=$a; done\n\
		 \t\tmkdir -p {shim}/xdg/systemd/user\n\
		 \t\tprintf '[Service]\\nExecStart=/usr/bin/podup%s -p epistle up -d --no-build --pull never\\n' \"$files\" > {shim}/xdg/systemd/user/podup-epistle.service\n\
		 \t\t: > {state}/loaded\n\
		 \t\tcase \"$*\" in *--no-start*) ;; *) : > {state}/enabled ;; esac ;;\n\
		 \t*autostart\\ uninstall*)\n\
		 \t\trm -f {shim}/xdg/systemd/user/podup-epistle.service {state}/loaded {state}/enabled ;;\n\
		 esac\n\
		 exit 0\n",
		log = log.display(),
		state = state.display(),
		shim = shim.display()
	)
}

fn systemctl_body(state: &Path) -> String {
	format!(
		"#!/bin/sh\n\
		 printf '%s\\n' \"$*\" >> {s}/systemctl.log\n\
		 case \"$*\" in\n\
		 \t--version) echo \"systemd ${{SYSTEMD_FAKE_VERSION:-255}} (255.4)\" ;;\n\
		 \t*is-enabled*) if [ -e {s}/enabled ]; then echo enabled; else echo disabled; fi ;;\n\
		 \t*\" enable \"*) : > {s}/enabled ;;\n\
		 \t*show*) if [ -e {s}/loaded ]; then echo LoadState=loaded; else echo LoadState=not-found; fi ;;\n\
		 esac\n\
		 exit 0\n",
		s = state.display()
	)
}

const INSTALL: &str = "autostart install --no-start";

/// The commands that leave the stack running, and one way to run each.
const PATHS: &[&[&str]] = &[
	&["apply"],
	&["restart"],
	&["restart", "mail"],
	&["start"],
	&["start", "mail"],
];

#[test]
fn every_path_installs_a_missing_unit_after_it_succeeds() {
	for args in PATHS {
		let world = World::new();
		let out = world.run(args);
		assert_eq!(
			out.status.code(),
			Some(0),
			"{args:?}: {}",
			String::from_utf8_lossy(&out.stderr)
		);
		assert!(
			world.installed(),
			"{args:?} left no unit; calls: {:?}",
			world.calls()
		);
		let verbs = world.verbs();
		assert_eq!(
			verbs.last().map(String::as_str),
			Some(INSTALL),
			"{args:?}: {verbs:?}"
		);
	}
}

#[test]
fn a_unit_that_is_fine_is_left_alone_so_a_second_run_changes_nothing() {
	for args in PATHS {
		let world = World::new();
		world.fine();
		let before = std::fs::read_to_string(&world.unit).unwrap();
		let out = world.run(args);
		assert_eq!(out.status.code(), Some(0), "{args:?}");
		assert!(
			!world.verbs().iter().any(|v| v == INSTALL),
			"{args:?} installed: {:?}",
			world.verbs()
		);
		assert_eq!(std::fs::read_to_string(&world.unit).unwrap(), before);
	}
	// And a run that installed leaves a unit the next run does not touch.
	let world = World::new();
	world.run(&["apply"]);
	assert!(world.verbs().iter().any(|v| v == INSTALL));
	world.run(&["apply"]);
	assert!(
		!world.verbs().iter().any(|v| v == INSTALL),
		"{:?}",
		world.verbs()
	);
}

#[test]
fn a_disabled_or_unloaded_or_stale_unit_is_installed_again() {
	type Spoil = fn(&World);
	let cases: [(&str, Spoil); 3] = [
		("disabled", |w| {
			std::fs::remove_file(w.state.join("enabled")).unwrap()
		}),
		("not loaded", |w| {
			std::fs::remove_file(w.state.join("loaded")).unwrap()
		}),
		("stale", |w| write_unit(&w.unit, "-f /gone/compose.yaml")),
	];
	for (name, spoil) in cases {
		let world = World::new();
		world.fine();
		spoil(&world);
		let out = world.run(&["apply"]);
		assert_eq!(out.status.code(), Some(0), "{name}");
		assert!(
			world.verbs().iter().any(|v| v == INSTALL),
			"{name}: {:?}",
			world.verbs()
		);
		let text = std::fs::read_to_string(&world.unit).unwrap();
		assert!(
			text.contains(&format!("-f {}", world.compose.display())),
			"{name}: {text}"
		);
	}
}

#[test]
fn an_override_file_that_appears_makes_the_unit_stale() {
	let world = World::new();
	world.fine();
	std::fs::write(
		world.compose.with_file_name("compose.override.yaml"),
		"services: {}\n",
	)
	.unwrap();
	world.run(&["apply"]);
	assert!(
		world.calls().iter().any(|call| call.ends_with(INSTALL)),
		"{:?}",
		world.calls()
	);
	let text = std::fs::read_to_string(&world.unit).unwrap();
	assert!(text.contains("compose.override.yaml"), "{text}");
}

#[test]
fn the_check_never_asks_podup_to_touch_a_container_or_an_image() {
	let touching = [
		"up",
		"build",
		"pull",
		"restart",
		"down",
		"stop",
		"start",
		"--force-recreate",
		"create",
		"rm",
	];
	for args in PATHS {
		for spoil in [false, true] {
			let world = World::new();
			if !spoil {
				world.fine();
			}
			world.run(args);
			// What the command itself runs is its own business; what the
			// check adds is only ever `autostart install --no-start`.
			let own = match args[0] {
				"apply" => vec!["up -d", "restart mail"],
				"restart" => vec![if args.len() > 1 {
					"restart mail"
				} else {
					"restart"
				}],
				_ => vec![if args.len() > 1 {
					"start mail"
				} else {
					"start"
				}],
			};
			for verb in world.verbs() {
				assert!(
					own.contains(&verb.as_str()) || verb == INSTALL,
					"{args:?} (spoiled: {spoil}) made the call {verb:?}"
				);
			}
			// The unit podup writes keeps the flags that make a boot a start.
			if let Ok(text) = std::fs::read_to_string(&world.unit) {
				assert!(text.contains("--no-build --pull never"), "{text}");
			}
			let _ = touching;
		}
	}
}

#[test]
fn stack_up_installs_the_unit_and_down_removes_it() {
	let world = World::new();
	let out = world.run(&["up"]);
	assert_eq!(out.status.code(), Some(0));
	assert!(world.installed());
	let out = world.run(&["down"]);
	assert_eq!(out.status.code(), Some(0));
	assert!(!world.installed(), "down must leave no unit");
	assert_eq!(world.verbs(), vec!["autostart uninstall", "down"]);
}

#[test]
fn stop_and_down_never_install_a_unit_and_a_stack_taken_down_stays_without_one() {
	let world = World::new();
	world.run(&["up"]);
	world.run(&["down"]);
	for args in [&["stop"][..], &["stop", "mail"][..], &["down"][..]] {
		let out = world.run(args);
		assert_eq!(out.status.code(), Some(0), "{args:?}");
		assert!(!world.installed(), "{args:?} installed a unit");
		assert!(
			!world.verbs().iter().any(|v| v == INSTALL),
			"{args:?}: {:?}",
			world.verbs()
		);
	}
}

#[test]
fn a_failing_command_does_not_check_the_unit() {
	let world = World::new();
	let failing = world.shim.join("podup");
	std::fs::write(&failing, "#!/bin/sh\ncase \"$*\" in --version) printf '\\npodup version v5.19.0\\n\\n'; exit 0;; esac\nexit 3\n").unwrap();
	let out = world.run(&["apply"]);
	assert_ne!(out.status.code(), Some(0));
	assert!(!world.installed());
}

#[test]
fn a_failed_install_warns_with_the_repair_and_keeps_the_exit_code_of_the_command() {
	let world = World::new();
	let body = podup_body(&world.log, &world.state, &world.shim).replace(
		"*autostart\\ install*)",
		"*autostart\\ install*) exit 1 ;;\n\t*never_matches*)",
	);
	std::fs::write(world.shim.join("podup"), body).unwrap();
	let out = world.run(&["apply"]);
	assert_eq!(
		out.status.code(),
		Some(0),
		"the command itself had succeeded"
	);
	let stderr = String::from_utf8_lossy(&out.stderr);
	assert!(
		stderr.contains("would not come back after a reboot"),
		"{stderr}"
	);
	assert!(stderr.contains("sudo epistle stack start"), "{stderr}");
}

#[test]
fn the_repair_never_starts_the_unit_it_installs() {
	for spoil in ["missing", "disabled"] {
		let world = World::new();
		if spoil == "disabled" {
			world.fine();
			std::fs::remove_file(world.state.join("enabled")).unwrap();
		}
		let out = world.run(&["apply"]);
		assert_eq!(out.status.code(), Some(0), "{spoil}");
		assert!(world.verbs().iter().any(|v| v == INSTALL), "{spoil}");
		let ctl = std::fs::read_to_string(world.state.join("systemctl.log")).unwrap();
		assert!(
			ctl.lines()
				.any(|l| l == "--user enable podup-epistle.service"),
			"{spoil}: the unit is enabled with a plain enable: {ctl}"
		);
		assert!(
			!ctl.contains("--now") && !ctl.contains(" start "),
			"{spoil}: the repair must not start the unit: {ctl}"
		);
		assert!(world.state.join("enabled").exists(), "{spoil}");
	}
}

/// Where the user drop-in of the boot unit lives in this world.
fn drop_in(world: &World) -> PathBuf {
	world
		.unit
		.with_file_name("podup-epistle.service.d")
		.join("10-epistle.conf")
}

fn reloads(world: &World) -> usize {
	std::fs::read_to_string(world.state.join("systemctl.log"))
		.unwrap_or_default()
		.lines()
		.filter(|line| *line == "--user daemon-reload")
		.count()
}

#[test]
fn stack_up_writes_the_retry_drop_in_and_down_removes_it() {
	let world = World::new();
	let out = world.run(&["up"]);
	assert_eq!(out.status.code(), Some(0));
	let text = std::fs::read_to_string(drop_in(&world)).expect("the drop-in is written");
	assert!(text.contains("Restart=on-failure"), "{text}");
	assert!(text.contains("RestartSec=30s"), "{text}");
	assert!(text.contains("StartLimitIntervalSec=0"), "{text}");
	assert!(
		!text.lines().any(|line| line.starts_with("Exec")),
		"a reboot must keep running the unit's own `up -d --no-build --pull never`: {text}"
	);
	assert_eq!(reloads(&world), 1, "the user manager reads it once");
	let out = world.run(&["down"]);
	assert_eq!(out.status.code(), Some(0));
	assert!(!drop_in(&world).exists(), "down must leave no drop-in");
	assert!(
		!drop_in(&world).parent().unwrap().exists(),
		"and no empty directory"
	);
}

#[test]
fn a_second_run_does_not_write_or_reload_the_drop_in_again() {
	let world = World::new();
	world.run(&["apply"]);
	let first = std::fs::metadata(drop_in(&world))
		.unwrap()
		.modified()
		.unwrap();
	assert_eq!(reloads(&world), 1);
	let out = world.run(&["apply"]);
	assert_eq!(out.status.code(), Some(0));
	assert_eq!(
		reloads(&world),
		1,
		"a drop-in that is current is not reloaded"
	);
	let second = std::fs::metadata(drop_in(&world))
		.unwrap()
		.modified()
		.unwrap();
	assert_eq!(first, second, "a drop-in that is current is not rewritten");
}

#[test]
fn stop_leaves_the_drop_in_and_start_writes_it() {
	let world = World::new();
	world.run(&["start"]);
	assert!(drop_in(&world).exists());
	let out = world.run(&["stop"]);
	assert_eq!(out.status.code(), Some(0));
	assert!(
		drop_in(&world).exists(),
		"stop leaves the unit and its drop-in"
	);
}

#[test]
fn the_configuration_turns_the_retry_drop_in_off() {
	let world = World::new();
	world.run(&["apply"]);
	assert!(drop_in(&world).exists());
	let mut config = std::fs::read_to_string(&world.cfg).unwrap();
	config.push_str("\n[boot]\nrestart_on_failure = false\n");
	std::fs::write(&world.cfg, config).unwrap();
	let out = world.run(&["apply"]);
	assert_eq!(out.status.code(), Some(0));
	assert!(
		!drop_in(&world).exists(),
		"the switch removes what was written"
	);
	world.run(&["apply"]);
	assert!(!drop_in(&world).exists(), "and nothing writes it again");
}

#[test]
fn a_systemd_older_than_244_gets_no_drop_in_and_a_warning() {
	let world = World::new();
	let ctl = world.shim.join("systemctl");
	let body = std::fs::read_to_string(&ctl)
		.unwrap()
		.replace("${SYSTEMD_FAKE_VERSION:-255}", "243");
	std::fs::write(&ctl, body).unwrap();
	let out = world.run(&["apply"]);
	assert_eq!(out.status.code(), Some(0));
	assert!(!drop_in(&world).exists());
	let stderr = String::from_utf8_lossy(&out.stderr);
	assert!(stderr.contains("older than 244"), "{stderr}");
}

#[test]
fn the_account_never_writes_the_system_drop_in() {
	// The suite does not run as root, and a process that is not root has no
	// way to write under /etc/systemd/system: it must not even try.
	let world = World::new();
	let out = world.run(&["up"]);
	assert_eq!(out.status.code(), Some(0));
	let stderr = String::from_utf8_lossy(&out.stderr);
	assert!(
		!stderr.contains("not ordered after the network"),
		"{stderr}"
	);
	let ctl = std::fs::read_to_string(world.state.join("systemctl.log")).unwrap();
	assert!(
		!ctl.lines().any(|line| line == "daemon-reload"),
		"the system manager is reloaded only by a root that wrote a drop-in: {ctl}"
	);
}
