//! The web panel's key: the run puts the new secret in the file the panel
//! reads, makes its container again, and prints the secret nowhere.

mod file;
mod kill;
mod service;
mod step;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::api::{ApiKey, ApiKeyStore};
use crate::cli::stack::StackAction;
use crate::config::Config;

use super::super::{Options, execute};

const NOW: u64 = 1_900_000_000;

/// The label of the key that is not the panel's.
const OTHER: &str = "ci";

/// An install with the secrets directory beside its data directory, as
/// `init` lays it out, and one API key that is not the panel's.
struct Install {
	_root: tempfile::TempDir,
	config: PathBuf,
	data: PathBuf,
}

fn install() -> Install {
	let root = tempfile::tempdir().unwrap();
	let base = root.path().canonicalize().unwrap();
	let data = base.join("data");
	std::fs::create_dir_all(&data).unwrap();
	let config = base.join("mail.toml");
	std::fs::write(
		&config,
		format!(
			"hostname = 'mail.example.org'\ndata_dir = {data:?}\ndomains = ['example.org']\n\n\
			 [[listeners]]\nkind = 'smtp'\naddr = '0.0.0.0'\n"
		),
	)
	.unwrap();
	// The configuration is refused when group or others can read it.
	std::fs::set_permissions(&config, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	let minted = crate::queue::srs::generate_secret().expect("random bytes");
	ApiKeyStore::open(&data)
		.unwrap()
		.add(ApiKey {
			label: OTHER.to_string(),
			hash: crate::api::api_keys::sha256_hash(&minted),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string()],
			domains: Vec::new(),
			account: None,
		})
		.unwrap();
	Install {
		_root: root,
		config,
		data,
	}
}

/// The account and the label of the app password [`app_password`] adds.
const APP: (&str, &str) = ("alice@example.org", "phone");

/// Give the install an app password and return its hash.
fn app_password(install: &Install) -> String {
	use crate::directory_store::app_passwords::{AppPassword, AppPasswordStore};
	let minted = crate::queue::srs::generate_secret().expect("random bytes");
	let hash = crate::smtp::auth::hash_password(&minted).unwrap();
	AppPasswordStore::open(&install.data)
		.unwrap()
		.add(
			APP.0,
			AppPassword {
				label: APP.1.to_string(),
				hash: hash.clone(),
				expires_at: None,
				ip_cidr: None,
				save_sent: None,
			},
		)
		.unwrap();
	hash
}

/// The stored hash of the app password [`app_password`] added.
fn app_password_hash(install: &Install) -> String {
	crate::directory_store::app_passwords::AppPasswordStore::open(&install.data)
		.unwrap()
		.for_account(APP.0)
		.iter()
		.find(|app| app.label == APP.1)
		.map(|app| app.hash.clone())
		.expect("the app password is still there")
}

/// [`install`] with the panel's key and files, as `init` leaves them.
fn install_with_panel() -> Install {
	let install = install();
	crate::cli::init::install_panel_for_tests(&install.data, NOW);
	install
}

/// Write a compose file that runs `services`.
fn compose(install: &Install, services: &[&str]) {
	let path = crate::cli::init::compose_file_path(&install.data);
	std::fs::create_dir_all(path.parent().unwrap()).unwrap();
	let services: serde_json::Map<String, serde_json::Value> = services
		.iter()
		.map(|name| ((*name).to_string(), serde_json::json!({})))
		.collect();
	let document = serde_json::json!({ "name": "epistle", "services": services });
	std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
}

/// Where the panel's key file is: the name is spelled here, so a change of
/// it in the code is seen.
fn key_file(install: &Install) -> PathBuf {
	crate::cli::init::host_secrets::dir(&install.data).join("panel_api_token")
}

fn stored(install: &Install, label: &str) -> String {
	ApiKeyStore::open(&install.data)
		.unwrap()
		.hash_of(label)
		.expect("the key is still there")
}

/// Whether the key file holds the secret of the stored `panel` key.
fn file_is_the_stored_key(install: &Install) -> bool {
	let secret = std::fs::read_to_string(key_file(install)).unwrap();
	crate::api::api_keys::sha256_hash(&secret) == stored(install, "panel")
}

/// What one run printed, how it ended and what it asked of the stack.
struct Ran {
	code: ExitCode,
	out: String,
	status: String,
	actions: Vec<String>,
}

/// Run the rotation with `--yes`, the stack answering `answer`.
fn run(config: &Path, now: u64, json: bool, answer: ExitCode) -> Ran {
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let mut actions = Vec::new();
	let options = Options {
		yes: true,
		json,
		now,
	};
	let code = execute(
		config,
		options,
		&mut out,
		&mut status,
		|_: &Config, action: StackAction| {
			actions.push(format!("{action:?}"));
			answer
		},
	);
	Ran {
		code,
		out: String::from_utf8(out).unwrap(),
		status: String::from_utf8(status).unwrap(),
		actions,
	}
}

/// The `kind` of every step of a `--json` result, in order.
fn kinds(out: &str) -> Vec<String> {
	let result: serde_json::Value = serde_json::from_str(out).expect("one JSON object");
	result["steps"]
		.as_array()
		.unwrap()
		.iter()
		.map(|step| step["kind"].as_str().unwrap().to_string())
		.collect()
}
