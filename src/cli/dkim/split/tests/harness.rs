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

/// A rewrite applied to every value published.
pub(super) type Tamper = fn(&str) -> String;

/// The published TXT records, by name.
#[derive(Clone, Default)]
pub(super) struct Zone {
	pub records: Arc<Mutex<HashMap<String, Vec<String>>>>,
	/// The `(name, value)` of every delete the provider was asked for.
	pub deleted: Arc<Mutex<Vec<(String, String)>>>,
	/// Rewrites every value the provider publishes, like a template that
	/// changes a record on the way in.
	pub tamper: Arc<Mutex<Option<Tamper>>>,
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
		let tamper = *self.zone.tamper.lock().unwrap();
		Box::pin(async move {
			if refuses {
				return Err(ProviderError::Unsupported);
			}
			let value = tamper.map_or_else(|| record.value.clone(), |f| f(&record.value));
			records.lock().unwrap().insert(record.name, vec![value]);
			Ok(())
		})
	}

	fn delete_exact(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
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

	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		panic!("dkim split --finish must delete by exact value, not by purpose")
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// How a provider that is not the strict one behaves.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Flaw {
	/// Keeps the trait default: it cannot match by value.
	NoExactDelete,
	/// Claims an exact delete but wipes every value at the name.
	Greedy,
	/// Claims an exact delete and removes nothing.
	Inert,
}

/// A provider with one of the [`Flaw`]s.
pub(super) struct Flawed {
	pub zone: Zone,
	pub flaw: Flaw,
}

impl DnsProvider for Flawed {
	fn upsert(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		panic!("not used")
	}

	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		panic!("dkim split --finish must delete by exact value, not by purpose")
	}

	fn delete_exact(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		let flaw = self.flaw;
		let records = Arc::clone(&self.zone.records);
		let deleted = Arc::clone(&self.zone.deleted);
		Box::pin(async move {
			match flaw {
				Flaw::NoExactDelete => return Err(ProviderError::Unsupported),
				Flaw::Inert => {}
				Flaw::Greedy => {
					records.lock().unwrap().remove(&record.name);
				}
			}
			deleted.lock().unwrap().push((record.name, record.value));
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
		Install::with_selector(domains, extra, "s1")
	}

	/// [`Install::new`] with the selector the shared key is published under.
	pub(super) fn with_selector(domains: &[&str], extra: &str, selector: &str) -> Install {
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
			 [dkim]\nselector = \"{selector}\"\nkey_file = {key:?}\n{extra}",
			list.join(", ")
		)
		.expect("write config");
		std::fs::set_permissions(&config, std::os::unix::fs::PermissionsExt::from_mode(0o600))
			.expect("chmod");
		let install = Install { dir, config };
		with_stack(&install);
		install
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
	run_with(
		install,
		options,
		provider.map(|p| Arc::new(p) as Arc<dyn DnsProvider>),
		resolver,
		json,
	)
}

/// [`run_as`] with any provider.
pub(super) fn run_with(
	install: &Install,
	options: &super::super::Options,
	provider: Option<Arc<dyn DnsProvider>>,
	resolver: &dyn DnsLookup,
	json: bool,
) -> (std::process::ExitCode, String, String, usize) {
	let config = install.load();
	let services = super::super::Services {
		provider,
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

/// Take the compose file away again: the server cannot be restarted from here.
pub(super) fn without_stack(install: &Install) {
	let compose = crate::cli::init::compose_file_path(&install.data());
	std::fs::remove_file(compose).expect("compose file");
}
