//! The config check names hosted domains that still share one SRS secret.

use std::time::SystemTime;

use super::check;
use crate::cli::status::Ctx;
use crate::cli::status::report::Level;
use crate::config::Config;
use crate::test_fixtures::fresh_secret;

/// A configuration that hosts two domains, plus `extra`.
fn ctx_for(dir: &std::path::Path, extra: &str) -> Ctx {
	let data = dir.join("data");
	std::fs::create_dir_all(&data).expect("data dir");
	let path = dir.join("mail.toml");
	let text = format!(
		"hostname = \"mail.example.org\"\ndomains = [\"a.example\", \"b.example\"]\n\
		 data_dir = {:?}\n{extra}\n",
		data.display().to_string()
	);
	std::fs::write(&path, text).expect("write config");
	std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
		.expect("chmod config");
	Ctx {
		config: Config::load(&path).map_err(|error| error.to_string()),
		path,
		now: SystemTime::now(),
		podup: "sh".to_string(),
		meminfo: dir.join("meminfo"),
		steady: std::time::Duration::ZERO,
	}
}

#[tokio::test]
async fn two_domains_on_one_secret_are_a_warning_naming_both() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx_for(dir.path(), &format!("srs_secret = \"{}\"", fresh_secret()));
	let report = check(&ctx).await;
	assert_eq!(report.status, Level::Warn, "{report:?}");
	let item = report
		.items
		.iter()
		.find(|item| item.name == "SRS secret")
		.expect("an SRS secret item");
	assert_eq!(item.status, Level::Warn);
	assert!(
		item.detail.contains("a.example, b.example"),
		"{}",
		item.detail
	);
	assert!(item.detail.contains("epistle srs split"), "{}", item.detail);
	assert!(
		report.detail.contains("2 domains share srs_secret"),
		"{}",
		report.detail
	);
}

#[tokio::test]
async fn domains_with_their_own_secret_leave_nothing_to_warn_about() {
	let dir = tempfile::tempdir().expect("tempdir");
	let extra = format!(
		"srs_secret = \"{}\"\n[[srs_domain]]\nname = \"a.example\"\nsecret = \"{}\"\n\
		 [[srs_domain]]\nname = \"b.example\"\nsecret = \"{}\"\n",
		fresh_secret(),
		fresh_secret(),
		fresh_secret()
	);
	let report = check(&ctx_for(dir.path(), &extra)).await;
	assert!(
		report.items.iter().all(|item| item.name != "SRS secret"),
		"{report:?}"
	);
}
