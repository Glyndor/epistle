//! The panel choice on the `--answers` path of `init`.

use super::super::detect::tests::base::Scripted;
use super::*;

const GOOD: &str = "ghcr.io/glyndor/epistle-panel:0.3.1\n";

/// A dry run over an answers file whose `[services]` table carries `services`,
/// with the pin file at `manifest`. Returns the exit code and what `init` said.
fn dry_run(
	dir: &std::path::Path,
	services: &str,
	manifest: &std::path::Path,
) -> (ExitCode, String) {
	let answers_file = dir.join("answers.toml");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 public_ipv4 = \"none\"\n\
		 public_ipv6 = \"none\"\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\
		 image = \"localhost/epistle:dev\"\n\n\
		 [services]\n\
		 database = false\n\
		 {services}",
		dir.join("data").display(),
		dir.join("etc").join("mail.toml").display(),
	);
	std::fs::write(&answers_file, body).expect("write answers");
	let args = Args {
		answers: Some(answers_file),
		dry_run: true,
		print_answers: false,
		json: false,
	};
	let probes = Probes {
		detector: &Scripted::found(None, None),
		resolver: &|| None,
		meminfo: std::path::Path::new("/nonexistent/meminfo"),
		panel_manifest: manifest,
		clock: &|| crate::clock::sync::HostClock::Synced,
	};
	let mut out = Vec::new();
	let code = run_with(args, &probes, &mut out);
	(code, String::from_utf8(out).expect("utf-8"))
}

#[test]
fn a_demanded_panel_without_the_package_is_refused_before_anything_is_planned() {
	let dir = tempfile::tempdir().expect("tempdir");
	let missing = dir.path().join("absent/image");
	let (code, out) = dry_run(dir.path(), "panel = true\n", &missing);
	assert_eq!(code, ExitCode::from(EXIT_INVALID), "{out}");
	assert!(!out.contains("dry-run: nothing was written"), "{out}");
}

#[test]
fn a_demanded_panel_with_the_package_and_the_api_is_accepted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let manifest = dir.path().join("image");
	std::fs::write(&manifest, GOOD).expect("write");
	let (code, out) = dry_run(dir.path(), "panel = true\napi = true\n", &manifest);
	assert_eq!(code, ExitCode::from(EXIT_OK), "{out}");
	assert!(!out.contains("management API is off"), "{out}");
}

#[test]
fn the_package_without_the_api_is_reported_and_init_goes_on() {
	let dir = tempfile::tempdir().expect("tempdir");
	let manifest = dir.path().join("image");
	std::fs::write(&manifest, GOOD).expect("write");
	let (code, out) = dry_run(dir.path(), "", &manifest);
	assert_eq!(code, ExitCode::from(EXIT_OK), "{out}");
	assert!(out.contains("the management API is off"), "{out}");
}

#[test]
fn an_unusable_pin_file_is_refused_unless_the_panel_is_declined() {
	let dir = tempfile::tempdir().expect("tempdir");
	let manifest = dir.path().join("image");
	std::fs::write(&manifest, "garbage\n").expect("write");
	let (code, out) = dry_run(dir.path(), "api = true\n", &manifest);
	assert_eq!(code, ExitCode::from(EXIT_INVALID), "{out}");
	let (code, out) = dry_run(dir.path(), "api = true\npanel = false\n", &manifest);
	assert_eq!(code, ExitCode::from(EXIT_OK), "{out}");
}

/// A `true` recorded by an earlier run is not a new demand: the package may
/// have been purged since, and `init` must still run.
#[test]
fn a_recorded_demand_whose_package_was_purged_is_a_note_not_a_refusal() {
	let dir = tempfile::tempdir().expect("tempdir");
	let missing = dir.path().join("absent/image");
	let compose = crate::cli::init::compose::compose_file_path(&dir.path().join("data"));
	std::fs::create_dir_all(compose.parent().expect("parent")).expect("dir");
	std::fs::write(&compose, "{\"x-epistle-panel\": true, \"services\": {}}\n").expect("compose");
	let (code, out) = dry_run(dir.path(), "api = true\n", &missing);
	assert_eq!(code, ExitCode::from(EXIT_OK), "{out}");
	assert!(
		out.contains("services.panel is true, but the epistle-panel package is not installed"),
		"{out}"
	);
	// The same demand in the answers file is still refused.
	let (code, _) = dry_run(dir.path(), "api = true\npanel = true\n", &missing);
	assert_eq!(code, ExitCode::from(EXIT_INVALID));
}

/// An existing stack records the choice in its compose file, and `init` run
/// again with no `panel` answer keeps it.
#[test]
fn init_keeps_the_choice_an_existing_stack_recorded() {
	let dir = tempfile::tempdir().expect("tempdir");
	let manifest = dir.path().join("image");
	std::fs::write(&manifest, GOOD).expect("write");
	let compose = crate::cli::init::compose::compose_file_path(&dir.path().join("data"));
	std::fs::create_dir_all(compose.parent().expect("parent")).expect("dir");
	std::fs::write(&compose, "{\"x-epistle-panel\": false, \"services\": {}}\n").expect("compose");
	let (code, out) = dry_run(dir.path(), "api = true\n", &manifest);
	assert_eq!(code, ExitCode::from(EXIT_OK), "{out}");
	// The recorded `false` stands, so a pin file that would be refused if it
	// were read does not stop the run.
	std::fs::write(&manifest, "garbage\n").expect("write");
	let (code, out) = dry_run(dir.path(), "api = true\n", &manifest);
	assert_eq!(code, ExitCode::from(EXIT_OK), "{out}");
}
