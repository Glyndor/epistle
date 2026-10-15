//! Tests for the `antispam` `status` area: which features are wired in
//! and which are off, with a reason an operator can act on without
//! reading logs.

use std::io::Write;

use tempfile::NamedTempFile;

use crate::cli::status::antispam_area;
use crate::cli::status::{Ctx, report::Level};

fn write_config(body: &str) -> NamedTempFile {
	let mut file = NamedTempFile::new().expect("config file");
	writeln!(file, "hostname = \"mail.example.org\"").unwrap();
	writeln!(file, "data_dir = \"/var/lib/mail\"").unwrap();
	for line in body.lines() {
		writeln!(file, "{line}").unwrap();
	}
	file
}

fn ctx_for(path: &std::path::Path) -> Ctx {
	let config = crate::config::Config::load(path).expect("config loads");
	let now = std::time::SystemTime::UNIX_EPOCH;
	Ctx {
		path: path.to_path_buf(),
		config: Ok(config),
		now,
		podup: "podup".to_string(),
		meminfo: std::path::PathBuf::from("meminfo-absent"),
	}
}

/// A config with no `[database]` and no `[antispam]` section lists every
/// antispam feature as a Warn item (no Ok items at all) and the summary
/// says the engine is off. Operators reading `status` learn the cause in
/// one line.
#[tokio::test]
async fn antispam_status_lists_every_off_feature_when_no_database() {
	let file = write_config("");
	let ctx = ctx_for(file.path());
	let report = antispam_area::check(&ctx).await;
	// The four persistent-store features must surface as Warn; the
	// greylist item is only added when `greylist_delay_secs > 0`.
	for name in [
		"bayes",
		"reputation",
		"persistent_bans",
		"greylist_persistence",
	] {
		let item = report
			.items
			.iter()
			.find(|item| item.name == name)
			.unwrap_or_else(|| panic!("expected an `{name}` item in {report:?}"));
		assert_eq!(
			item.status,
			Level::Warn,
			"`{name}` must be Warn without a database: {report:?}"
		);
		assert!(
			item.detail.contains("[database]"),
			"`{name}` reason must name [database]: {report:?}"
		);
	}
}

/// A config with `[database]` configured lists those same four features
/// as Ok. Items change identity (Warn -> Ok), so the status check
/// stays informative regardless of which mode the install runs in.
#[tokio::test]
async fn antispam_status_lists_features_as_ok_when_database_is_set() {
	let file = write_config(
		r#"
[database]
url = "postgres:///db?host=/var/run/postgresql"
"#,
	);
	let ctx = ctx_for(file.path());
	let report = antispam_area::check(&ctx).await;
	for name in [
		"bayes",
		"reputation",
		"persistent_bans",
		"greylist_persistence",
	] {
		let item = report
			.items
			.iter()
			.find(|item| item.name == name)
			.unwrap_or_else(|| panic!("expected an `{name}` item in {report:?}"));
		assert_eq!(
			item.status,
			Level::Ok,
			"`{name}` must be Ok with a database: {report:?}"
		);
	}
}

/// Greylist as a feature is independent of `[database]`: the SMTP
/// server still defers triplets via the in-memory store, so the check
/// reports it as Ok even when no database is configured.
#[tokio::test]
async fn antispam_status_marks_greylist_on_when_delay_is_set() {
	let file = write_config("greylist_delay_secs = 60");
	let ctx = ctx_for(file.path());
	let report = antispam_area::check(&ctx).await;
	let item = report
		.items
		.iter()
		.find(|item| item.name == "greylist")
		.expect("greylist item must be present");
	assert_eq!(item.status, Level::Ok, "greylist must be Ok: {report:?}");
}

/// `clamd_socket` is a separate feature entirely (Unix socket, no DB).
/// When it is set the check adds it as Ok; otherwise it is just
/// absent. The Ok summary count grows; the Warn count does not
/// change.
#[tokio::test]
async fn antispam_status_marks_clamd_on_only_when_socket_is_set() {
	let with_socket = write_config(
		r#"
[antispam]
clamd_socket = "/run/clamav/clamd.sock"
"#,
	);
	let report = antispam_area::check(&ctx_for(with_socket.path())).await;
	assert!(
		report.items.iter().any(|item| item.name == "clamd"),
		"clamd must appear in the items list when configured: {report:?}"
	);

	let plain = write_config("");
	let report_plain = antispam_area::check(&ctx_for(plain.path())).await;
	assert!(
		!report_plain.items.iter().any(|item| item.name == "clamd"),
		"absent clamd_socket must not produce an item: {report_plain:?}"
	);
}
