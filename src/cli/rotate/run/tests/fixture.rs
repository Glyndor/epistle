//! A server with something of every kind the run rotates without a DKIM
//! setup: two API keys, an app password, a webhook secret and a domain's SRS
//! secret. Every secret is minted, so none is a literal in the source.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::api::{ApiKey, ApiKeyStore};
use crate::cli::stack::StackAction;
use crate::config::Config;
use crate::directory_store::app_passwords::{AppPassword, AppPasswordStore};

use super::super::{Options, execute};

/// The API key labels the fixture creates.
pub(super) const KEYS: [&str; 2] = ["ci", "panel"];

/// The account and label of its app password.
pub(super) const APP: (&str, &str) = ("alice@example.org", "phone");

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
	Server {
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
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let mut restarts = 0;
	let options = Options {
		yes: true,
		json: true,
		now,
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
