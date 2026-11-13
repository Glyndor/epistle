use std::process::ExitCode;

use super::{PanelCli, execute_with};
use crate::cli::init::panel_admin_id;
use crate::cli::resource::ResourceError;

const MINE: &str = "3f2b8c1e-5d4a-4b7e-9c3d-1a2b3c4d5e6f";

/// An install layout: `data_dir` with the secrets directory beside it.
struct Install {
	_root: tempfile::TempDir,
	data: std::path::PathBuf,
}

fn install(admin_id: Option<&str>) -> Install {
	let root = tempfile::tempdir().expect("tempdir");
	let data = root.path().join("data");
	std::fs::create_dir_all(&data).expect("data dir");
	if let Some(content) = admin_id {
		let secrets = root.path().join("secrets");
		std::fs::create_dir_all(&secrets).expect("secrets dir");
		std::fs::write(secrets.join("panel_admin_id"), content).expect("write");
	}
	Install { _root: root, data }
}

struct Shown {
	result: Result<ExitCode, ResourceError>,
	out: String,
	status: String,
}

fn show(install: &Install, json: bool) -> Shown {
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = execute_with(
		&install.data,
		PanelCli::AdminId { json: false },
		json,
		&mut out,
		&mut status,
	);
	Shown {
		result,
		out: String::from_utf8(out).expect("utf8"),
		status: String::from_utf8(status).expect("utf8"),
	}
}

#[test]
fn the_id_is_alone_on_stdout_and_the_path_and_the_warning_are_on_stderr() {
	let shown = show(&install(Some(&format!("{MINE}\n"))), false);
	assert!(shown.result.is_ok());
	assert_eq!(shown.out, format!("{MINE}\n"));
	assert!(
		shown.status.contains(&format!("/app/{MINE}")),
		"{}",
		shown.status
	);
	assert!(
		shown.status.contains("not a cryptographic secret"),
		"{}",
		shown.status
	);
	assert!(shown.status.contains("do not publish"), "{}", shown.status);
}

#[test]
fn json_is_one_object_with_the_id_and_the_path_and_no_note() {
	let shown = show(&install(Some(MINE)), true);
	assert!(shown.result.is_ok());
	let value: serde_json::Value = serde_json::from_str(&shown.out).expect("one JSON document");
	assert_eq!(value["admin_id"], MINE);
	assert_eq!(value["path"], format!("/app/{MINE}"));
	assert_eq!(shown.status, "", "notes stay out of the JSON run");
}

#[test]
fn the_leaf_flag_gives_the_same_json() {
	let install = install(Some(MINE));
	let mut out = Vec::new();
	let code = execute_with(
		&install.data,
		PanelCli::AdminId { json: true },
		false,
		&mut out,
		&mut Vec::new(),
	)
	.expect("shown");
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(
		String::from_utf8(out).expect("utf8"),
		show(&install, true).out
	);
}

#[test]
fn no_id_yet_is_a_refusal_that_says_how_to_get_one() {
	let shown = show(&install(None), false);
	let Err(ResourceError::Refusal(message)) = shown.result else {
		panic!("a missing id is a refusal, not a failure");
	};
	assert!(message.contains("epistle stack update"), "{message}");
	assert_eq!((shown.out.as_str(), shown.status.as_str()), ("", ""));
}

#[test]
fn a_file_that_is_not_an_id_is_an_error_and_nothing_of_it_is_printed() {
	for content in ["not-an-id", "TOP-SECRET-IN-THE-WRONG-FILE", "a\nb"] {
		let install = install(Some(content));
		for json in [false, true] {
			let shown = show(&install, json);
			let Err(ResourceError::Failure(message)) = shown.result else {
				panic!("{content:?} must be an error");
			};
			assert!(!message.contains(content), "{message}");
			assert_eq!((shown.out.as_str(), shown.status.as_str()), ("", ""));
		}
		assert!(panel_admin_id(&install.data).is_err());
	}
}

#[test]
fn the_command_parses_with_the_config_before_or_after() {
	use clap::Parser;
	for argv in [
		["epistle", "panel", "admin-id", "--config", "/x.toml"],
		["epistle", "panel", "--config", "/x.toml", "admin-id"],
	] {
		let crate::cli::Cli {
			command: crate::cli::Command::Panel { config, .. },
			..
		} = crate::cli::Cli::try_parse_from(argv).expect("parses")
		else {
			panic!("panel arguments must select the panel command");
		};
		assert_eq!(config, std::path::Path::new("/x.toml"));
	}
}
