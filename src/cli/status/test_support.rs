//! Helpers shared by the status check tests.

use std::path::Path;
use std::time::SystemTime;

use super::Ctx;
use crate::config::Config;

/// Write `<dir>/mail.toml` with a hostname, `data_dir = <dir>/data` and the
/// extra TOML given, then load it into a context.
pub(super) fn ctx(dir: &Path, extra: &str) -> Ctx {
	let data = dir.join("data");
	std::fs::create_dir_all(&data).expect("data dir");
	let path = dir.join("mail.toml");
	let text = format!(
		"hostname = \"mail.example.org\"\ndomains = [\"example.org\"]\ndata_dir = {:?}\n{extra}\n",
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
	}
}
