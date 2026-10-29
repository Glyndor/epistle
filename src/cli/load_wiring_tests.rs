//! Which commands read the configuration strictly. A file the validation
//! refuses is read by `epistle status` alone, to report on it; every command
//! that acts on the data or serves mail refuses it. The wiring is fixed here
//! by the text of the call sites, because the commands that need root, a
//! database or a terminal cannot be driven from a unit test.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn source(relative: &str) -> String {
	std::fs::read_to_string(root().join(relative)).expect(relative)
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
	for entry in std::fs::read_dir(dir).expect("read_dir").flatten() {
		let path = entry.path();
		if path.is_dir() {
			rust_files(&path, out);
		} else if path.extension().is_some_and(|ext| ext == "rs") {
			out.push(path);
		}
	}
}

/// The lenient load is called from `status` and from the tests of the
/// loader, and from nowhere else.
#[test]
fn only_status_reads_the_configuration_leniently() {
	let mut files = Vec::new();
	rust_files(&root(), &mut files);
	let mut users: Vec<String> = files
		.iter()
		.filter(|path| {
			std::fs::read_to_string(path).is_ok_and(|text| {
				text.contains("load_lenient(") && !text.contains("fn load_lenient(")
			})
		})
		.map(|path| path.strip_prefix(root()).unwrap().display().to_string())
		.filter(|name| {
			!name.starts_with("config/")
				&& !name.starts_with("cli/status/")
				&& name != "cli/load_wiring_tests.rs"
		})
		.collect();
	users.sort();
	assert!(
		users.is_empty(),
		"lenient load used outside status: {users:?}"
	);
}

#[test]
fn status_reads_the_configuration_leniently() {
	assert!(source("cli/status/mod.rs").contains("Config::load_lenient(path)"));
}

#[test]
fn the_commands_that_act_on_the_data_read_it_strictly() {
	let dispatch = source("cli/dispatch/mod.rs");
	let backup = dispatch
		.split("Command::Backup { config }")
		.nth(1)
		.and_then(|rest| rest.lines().next())
		.expect("the backup arm");
	assert!(backup.contains("with_config(&config"), "{backup}");
	let serve = dispatch
		.split("Command::Serve { config }")
		.nth(1)
		.and_then(|rest| rest.lines().next())
		.expect("the serve arm");
	assert!(serve.contains("Config::load(&config)"), "{serve}");
	assert!(source("cli/dispatch/restore/mod.rs").contains("Config::load(&config)"));
	assert!(source("cli/stack/rollback/run.rs").contains("Config::load(config_path)"));
}
