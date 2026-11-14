//! A configuration file and a data directory for the tests of the domain
//! state, and the tests of the live state.

use std::io::Write;
use std::path::PathBuf;

use crate::config::Config;

use super::DomainsFile;

mod live;

/// A configuration file hosting `example.org` and `other.example.org` in a
/// data directory of its own, with `extra` appended.
pub(super) struct Fixture {
	_dir: tempfile::TempDir,
	pub config: PathBuf,
	pub data_dir: PathBuf,
}

impl Fixture {
	pub fn new(extra: &str) -> Self {
		Self::with_domains("[\"example.org\", \"other.example.org\"]", extra)
	}

	pub fn with_domains(domains: &str, extra: &str) -> Self {
		let dir = tempfile::tempdir().unwrap();
		let data_dir = dir.path().canonicalize().unwrap();
		let config = data_dir.join("mail.toml");
		let fixture = Fixture {
			_dir: dir,
			config,
			data_dir,
		};
		fixture.write_config(domains, extra);
		fixture
	}

	/// Replace the configuration file, as an operator editing it would.
	pub fn write_config(&self, domains: &str, extra: &str) {
		let mut file = std::fs::File::create(&self.config).unwrap();
		write!(
			file,
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = {domains}\n{extra}\n",
			self.data_dir.to_string_lossy()
		)
		.unwrap();
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			std::fs::set_permissions(&self.config, std::fs::Permissions::from_mode(0o600)).unwrap();
		}
	}

	pub fn load(&self) -> Config {
		Config::load(&self.config).expect("the configuration loads")
	}

	pub fn state_path(&self) -> PathBuf {
		super::path(&self.data_dir)
	}

	pub fn state(&self) -> Option<DomainsFile> {
		DomainsFile::read(&self.state_path()).unwrap()
	}

	pub fn write_state(&self, text: &str) {
		std::fs::write(self.state_path(), text).unwrap();
	}
}
