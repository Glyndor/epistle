//! A data directory with two accounts, a server key and two tenant keys.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::config::{Storage, Tenant};
use crate::storage::{AccountAddresses, MessageCrypto, generate_key_base64};

/// When every fixture message claims to have arrived.
pub(crate) fn arrival() -> SystemTime {
	SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

struct Table;

impl AccountAddresses for Table {
	fn addresses_for(&self, account: &str) -> Vec<String> {
		match account {
			"alice" => vec!["alice@acme.test".into()],
			"bob" => vec!["bob@plain.test".into()],
			_ => Vec::new(),
		}
	}
}

pub(crate) struct Fixture {
	pub(crate) dir: tempfile::TempDir,
	keys: Vec<PathBuf>,
}

impl Fixture {
	pub(crate) fn data_dir(&self) -> &Path {
		self.dir.path()
	}

	/// The crypto a run uses: server key, acme's key, and the account map.
	pub(crate) fn crypto(&self) -> MessageCrypto {
		self.crypto_with(&[("acme", "acme.test", 1)], false)
	}

	/// [`crypto`](Self::crypto) with `[storage] tenant_keys` set as given.
	pub(crate) fn crypto_writing(&self, tenant_keys: bool) -> MessageCrypto {
		self.crypto_with(&[("acme", "acme.test", 1)], tenant_keys)
	}

	/// The crypto of a release without tenant keys: the server key only.
	pub(crate) fn server_only(&self) -> MessageCrypto {
		self.crypto_with(&[], false)
	}

	/// A crypto holding globex's key instead of acme's.
	pub(crate) fn globex(&self) -> MessageCrypto {
		self.crypto_with(&[("globex", "globex.test", 2)], false)
	}

	fn crypto_with(&self, tenants: &[(&str, &str, usize)], tenant_keys: bool) -> MessageCrypto {
		let storage = Storage {
			encrypt_at_rest: true,
			tenant_keys,
			encryption_key_file: Some(self.keys[0].clone()),
			..Storage::default()
		};
		let tenants: Vec<Tenant> = tenants
			.iter()
			.map(|(name, domain, key)| Tenant {
				name: Some((*name).into()),
				domains: vec![(*domain).into()],
				quota_bytes: None,
				max_accounts: None,
				max_domains: None,
				submission_rate_limit_per_min: None,
				encryption_key_file: Some(self.keys[*key].clone()),
				webhook: None,
			})
			.collect();
		let crypto = MessageCrypto::from_parts(Some(&storage), &tenants).expect("crypto");
		crypto.attach_accounts(Arc::new(Table));
		crypto
	}

	/// Store `body` for `account` under the server key, dated [`arrival`].
	pub(crate) fn store(&self, account: &str, relative: &str, body: &[u8]) -> PathBuf {
		let bytes = self.server_only().encode(body).expect("seal");
		self.write_raw(account, relative, &bytes)
	}

	/// Write `bytes` as they are.
	pub(crate) fn write_raw(&self, account: &str, relative: &str, bytes: &[u8]) -> PathBuf {
		let path = self
			.data_dir()
			.join("accounts")
			.join(account)
			.join(relative);
		std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
		std::fs::write(&path, bytes).expect("write");
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
		std::fs::File::options()
			.write(true)
			.open(&path)
			.expect("open")
			.set_modified(arrival())
			.expect("mtime");
		path
	}

	/// Every regular file under the account trees, temporaries included.
	pub(crate) fn files(&self) -> Vec<PathBuf> {
		let mut out = Vec::new();
		for root in ["accounts", "blobs"] {
			crate::storage::rekey::collect(&self.data_dir().join(root), &mut out).expect("walk");
		}
		out.sort();
		out
	}
}

pub(crate) fn fixture() -> Fixture {
	let dir = tempfile::tempdir().expect("tempdir");
	let keys = ["server", "acme", "globex"]
		.iter()
		.map(|name| {
			let path = dir.path().join(format!("{name}.key"));
			std::fs::write(&path, generate_key_base64().expect("csprng")).expect("key");
			std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
			path
		})
		.collect();
	Fixture { dir, keys }
}
