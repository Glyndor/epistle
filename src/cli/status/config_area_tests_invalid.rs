//! `status` on a file the validation refuses: the config area says so, and
//! the file stays loaded for the other areas.

use super::super::{Ctx, report::Level};
use crate::config::Config;

#[tokio::test]
async fn an_invalid_file_fails_the_config_area_with_the_reason() {
	let mut file = tempfile::NamedTempFile::new().expect("temp");
	std::io::Write::write_all(
		&mut file,
		b"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n[[alias]]\naddress = \"team@example.org\"\nmembers = []\n",
	)
	.expect("write");
	let config = Config::load_lenient(file.path()).expect("lenient load");
	let ctx = Ctx {
		path: file.path().to_path_buf(),
		config: Ok(config),
		now: std::time::SystemTime::UNIX_EPOCH,
		podup: "podup".to_string(),
		meminfo: std::path::PathBuf::from("meminfo-absent"),
	};
	let report = super::check(&ctx).await;
	assert!(report.status == Level::Fail);
	assert!(
		report.detail.contains("does not pass validation"),
		"{}",
		report.detail
	);
	assert!(
		report.detail.contains("has no members"),
		"{}",
		report.detail
	);
}
