//! A server with something of every kind the run rotates without a DKIM
//! setup: two API keys, an app password, a webhook secret, a domain's SRS
//! secret and an account with a password and a second factor. Every secret
//! is minted, so none is a literal in the source.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::api::{ApiKey, ApiKeyStore};
use crate::cli::stack::StackAction;
use crate::config::Config;
use crate::directory_store::app_passwords::{AppPassword, AppPasswordStore};

use super::super::{Options, Scope, execute};

/// The API key labels the fixture creates.
pub(super) const KEYS: [&str; 2] = ["ci", "panel"];

/// The account and label of its app password.
pub(super) const APP: (&str, &str) = ("alice@example.org", "phone");

/// The dynamic account the run resets.
pub(super) const ACCOUNT: &str = "bob";

/// A server on disk and the secrets it started with.
pub(super) struct Server {
	/// Holds the data directory and the configuration alive.
	_dir: tempfile::TempDir,
	_file: tempfile::NamedTempFile,
	pub config: PathBuf,
	pub data_dir: PathBuf,
	/// The hash of each API key before the run.
	pub key_hashes: Vec<String>,
	/// The PHC hash of the app password before the run.
	pub app_hash: String,
	/// The webhook secret and the SRS secret the file started with.
	pub webhook: String,
	pub srs: String,
	/// The password hash of [`ACCOUNT`] before the run.
	pub account_hash: String,
}

fn minted() -> String {
	crate::queue::srs::generate_secret().expect("random bytes")
}

/// Build the server.
pub(super) fn server() -> Server {
	let (webhook, srs) = (minted(), minted());
	let extra = format!(
		"\n[webhook]\nurl = 'https://hooks.example.net/epistle'\nsecret = '{webhook}'\n\n\
		 [[srs_domain]]\nname = 'example.org'\nsecret = '{srs}'\n"
	);
	let (dir, file) = crate::cli::resource::test_config(&extra);
	let data_dir = dir.path().canonicalize().unwrap();
	let mut keys = ApiKeyStore::open(&data_dir).unwrap();
	let mut key_hashes = Vec::new();
	for label in KEYS {
		let hash = crate::api::api_keys::sha256_hash(&minted());
		keys.add(ApiKey {
			label: label.to_string(),
			hash: hash.clone(),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string()],
			domains: Vec::new(),
			account: None,
		})
		.unwrap();
		key_hashes.push(hash);
	}
	let app_hash = crate::smtp::auth::hash_password(&minted()).unwrap();
	AppPasswordStore::open(&data_dir)
		.unwrap()
		.add(
			APP.0,
			AppPassword {
				label: APP.1.to_string(),
				hash: app_hash.clone(),
				expires_at: None,
				ip_cidr: None,
				save_sent: None,
			},
		)
		.unwrap();
	let account_hash = add_account(&data_dir, ACCOUNT);
	Server {
		account_hash,
		config: file.path().to_path_buf(),
		_dir: dir,
		_file: file,
		data_dir,
		key_hashes,
		app_hash,
		webhook,
		srs,
	}
}

/// The account store of the server, as a fresh process opens it.
pub(super) fn accounts(data_dir: &Path) -> crate::directory_store::AccountStore {
	crate::directory_store::AccountStore::open(
		data_dir,
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.unwrap()
}

/// Add a dynamic account with a minted password and a second factor, and
/// return its password hash.
pub(super) fn add_account(data_dir: &Path, name: &str) -> String {
	let hash = crate::smtp::auth::hash_password(&minted()).unwrap();
	accounts(data_dir)
		.add(crate::directory_store::DynamicAccount {
			name: name.to_string(),
			addresses: vec![format!("{name}@example.org")],
			password_hash: hash.clone(),
			totp_secret: Some(crate::totp::encode_base32(&[3u8; 20])),
			..crate::directory_store::DynamicAccount::default()
		})
		.unwrap();
	hash
}

/// What one run printed and how it ended.
pub(super) struct Ran {
	pub code: ExitCode,
	pub out: String,
	pub status: String,
	/// How many times the restart was asked for.
	pub restarts: usize,
}

/// Run the rotation of `config` as the operator would with `--yes --json`.
pub(super) fn run(config: &Path, now: u64) -> Ran {
	run_scoped(config, now, Scope::All)
}

/// [`run`] for one scope.
pub(super) fn run_scoped(config: &Path, now: u64, scope: Scope) -> Ran {
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let mut restarts = 0;
	let options = Options {
		yes: true,
		json: true,
		now,
		scope,
	};
	let code = execute(
		config,
		options,
		&mut out,
		&mut status,
		|_: &Config, _: StackAction| {
			restarts += 1;
			ExitCode::SUCCESS
		},
	);
	Ran {
		code,
		out: String::from_utf8(out).unwrap(),
		status: String::from_utf8(status).unwrap(),
		restarts,
	}
}

/// The rotation directory of the server.
pub(super) fn rotate_dir(server: &Server) -> PathBuf {
	server.data_dir.join("rotate")
}
