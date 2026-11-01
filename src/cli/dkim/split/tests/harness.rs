//! A DNS zone the provider writes and a resolver reads, and a configuration
//! on disk that `dkim split` edits.

use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError};
use crate::spf::{DnsFailure, DnsLookup};

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// The published TXT records, by name.
#[derive(Clone, Default)]
pub(super) struct Zone {
	pub records: Arc<Mutex<HashMap<String, Vec<String>>>>,
	/// The `(name, value)` of every delete the provider was asked for.
	pub deleted: Arc<Mutex<Vec<(String, String)>>>,
}

impl Zone {
	pub(super) fn published(&self) -> Vec<String> {
		let mut names: Vec<_> = self.records.lock().unwrap().keys().cloned().collect();
		names.sort();
		names
	}
}

/// A provider that writes into the zone, or refuses every write.
pub(super) struct Provider {
	pub zone: Zone,
	pub refuses: bool,
}

impl DnsProvider for Provider {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		let refuses = self.refuses;
		let records = Arc::clone(&self.zone.records);
		Box::pin(async move {
			if refuses {
				return Err(ProviderError::Unsupported);
			}
			records
				.lock()
				.unwrap()
				.insert(record.name, vec![record.value]);
			Ok(())
		})
	}

	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		let records = Arc::clone(&self.zone.records);
		let deleted = Arc::clone(&self.zone.deleted);
		Box::pin(async move {
			deleted
				.lock()
				.unwrap()
				.push((record.name.clone(), record.value.clone()));
			// Like a real provider: only the record with that exact value goes.
			let mut records = records.lock().unwrap();
			if let Some(values) = records.get_mut(&record.name) {
				values.retain(|value| *value != record.value);
				if values.is_empty() {
					records.remove(&record.name);
				}
			}
			Ok(())
		})
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// A resolver that shows the zone, or shows nothing (`blind`).
pub(super) struct Resolver {
	pub zone: Zone,
	pub blind: bool,
}

impl DnsLookup for Resolver {
	fn txt(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let seen = if self.blind {
			Vec::new()
		} else {
			self.zone
				.records
				.lock()
				.unwrap()
				.get(name)
				.cloned()
				.unwrap_or_default()
		};
		Box::pin(async move { Ok(seen) })
	}

	fn addresses(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// A resolver that cannot answer.
pub(super) struct Failing;

impl DnsLookup for Failing {
	fn txt(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Err(DnsFailure::Temporary) })
	}

	fn addresses(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// A directory with a key, a configuration (mode 0600) and its data directory.
pub(super) struct Install {
	pub dir: tempfile::TempDir,
	pub config: PathBuf,
}

impl Install {
	/// `domains` all sign with the `[dkim]` key; `extra` is appended.
	pub(super) fn new(domains: &[&str], extra: &str) -> Install {
		let dir = tempfile::tempdir().expect("dir");
		let data = dir.path().canonicalize().expect("path").join("data");
		std::fs::create_dir_all(&data).expect("data");
		let (pem, _) = crate::dkim::generate_key().expect("key");
		let key = dir.path().join("default.pem");
		std::fs::write(&key, pem).expect("write");
		let list: Vec<String> = domains.iter().map(|d| format!("{d:?}")).collect();
		let config = dir.path().join("mail.toml");
		let mut file = std::fs::File::create(&config).expect("config");
		write!(
			file,
			"hostname = \"mail.example.org\"\ndata_dir = {data:?}\ndomains = [{}]\n\
			 [dns]\nprovider = \"cloudflare\"\nzone = \"example.org\"\ntoken = \"t\"\n\
			 [dkim]\nselector = \"s1\"\nkey_file = {key:?}\n{extra}",
			list.join(", ")
		)
		.expect("write config");
		std::fs::set_permissions(&config, std::os::unix::fs::PermissionsExt::from_mode(0o600))
			.expect("chmod");
		Install { dir, config }
	}

	pub(super) fn text(&self) -> String {
		std::fs::read_to_string(&self.config).expect("config text")
	}

	pub(super) fn data(&self) -> PathBuf {
		self.dir.path().canonicalize().expect("path").join("data")
	}

	pub(super) fn load(&self) -> crate::config::Config {
		crate::config::Config::load(&self.config).expect("config loads")
	}
}

/// Run `dkim split` against `install` with the services given, returning the
/// exit code, stdout, stderr and how many times the server was restarted.
pub(super) fn run(
	install: &Install,
	options: &super::super::Options,
	provider: Option<Provider>,
	resolver: &dyn DnsLookup,
) -> (std::process::ExitCode, String, String, usize) {
	run_as(install, options, provider, resolver, false)
}

/// [`run`], printing the result as JSON when `json` is set.
pub(super) fn run_as(
	install: &Install,
	options: &super::super::Options,
	provider: Option<Provider>,
	resolver: &dyn DnsLookup,
	json: bool,
) -> (std::process::ExitCode, String, String, usize) {
	let config = install.load();
	let services = super::super::Services {
		provider: provider.map(|p| Arc::new(p) as Arc<dyn DnsProvider>),
		resolver,
		waits: vec![std::time::Duration::ZERO; 2],
	};
	let (mut out, mut err) = (Vec::new(), Vec::new());
	let restarts = std::cell::Cell::new(0usize);
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_time()
		.build()
		.expect("runtime");
	let code = runtime.block_on(super::super::split(
		&install.config,
		&config,
		options,
		&services,
		(json, &mut out, &mut err),
		|_, _| {
			restarts.set(restarts.get() + 1);
			std::process::ExitCode::SUCCESS
		},
	));
	(
		code,
		String::from_utf8_lossy(&out).into_owned(),
		String::from_utf8_lossy(&err).into_owned(),
		restarts.get(),
	)
}

/// A compose file, so a changed configuration restarts the server.
pub(super) fn with_stack(install: &Install) {
	let compose = crate::cli::init::compose_file_path(&install.data());
	std::fs::create_dir_all(compose.parent().expect("dir")).expect("dir");
	std::fs::write(compose, "services: {}\n").expect("compose");
}

/// The public key of an ed25519 key file.
pub(super) fn public(file: &Path) -> String {
	crate::dkim::Signer::load("x", file)
		.expect("loads")
		.dns_record_value()
}
