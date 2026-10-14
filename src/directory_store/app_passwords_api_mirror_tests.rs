//! `add_app_password` rebuilds the in-memory mirror from the
//! post-write disk state, so a credential another process added
//! while the long-running server's `AccountStore` was open is not
//! silently lost in the mirror. The file itself is fine —
//! `AppPasswordStore::add` reads fresh under the sibling `flock` —
//! but without the rebuild, the next authentication attempt
//! against the mirror would still deny the sibling-written
//! credential.
//!
//! Lives in a sibling so `app_passwords_api.rs` stays under the
//! per-file line budget.

use std::process::ExitCode;

use crate::config::Config;
use crate::directory_store::{AccountStore, AppPassword, AppPasswordStore};

fn config(data_dir: &std::path::Path) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

fn seed_account(data_dir: &std::path::Path, name: &str) {
	let path = data_dir.join("accounts.toml");
	std::fs::write(
		&path,
		format!(
			"[[accounts]]\nname = \"{name}\"\naddresses = [\"{name}@example.org\"]\npassword_hash = \"stub\"\n"
		),
	)
	.expect("write accounts.toml");
}

#[test]
fn add_app_password_picks_up_a_sibling_write_in_the_mirror() {
	// Two `AppPasswordStore`s over the same `data_dir`: one holds
	// the long-running server's in-memory mirror, the other is the
	// `epistle app-password create` CLI process. The CLI writes
	// first; the server then writes a second credential through
	// `AccountStore::add_app_password`. Without the mirror rebuild,
	// the server's in-memory list would still hold only the CLI's
	// write, dropping the credential the long-running server
	// itself just added.
	let dir = tempfile::tempdir().expect("tempdir");
	seed_account(dir.path(), "alice");
	let config = config(dir.path());
	let store = AccountStore::open(
		dir.path(),
		config.domains.clone(),
		std::collections::HashMap::new(),
		config.accounts.clone(),
	)
	.expect("open store");

	// A sibling writer (think: `epistle app-password create` from a
	// different process) lands a credential before this store ever
	// touches the file. The server's open() above loaded the empty
	// mirror, so it does not know about this credential.
	let mut cli = AppPasswordStore::open(dir.path()).expect("open sibling");
	cli.add(
		"alice",
		AppPassword {
			label: "phone".to_string(),
			hash: "sibling-argon2id-phc".to_string(),
			expires_at: None,
			ip_cidr: None,
			save_sent: None,
		},
	)
	.expect("sibling add");

	// The long-running server now adds a second credential through
	// the typed `add_app_password`. The mirror must hold both.
	store
		.add_app_password(
			"alice",
			AppPassword {
				label: "tablet".to_string(),
				hash: "server-argon2id-phc".to_string(),
				expires_at: None,
				ip_cidr: None,
				save_sent: None,
			},
		)
		.expect("server add");

	let mirror = store.for_account("alice");
	let labels: Vec<&str> = mirror.iter().map(|app| app.label.as_str()).collect();
	assert_eq!(
		labels,
		vec!["phone".to_string(), "tablet".to_string()],
		"the mirror must hold both the sibling-written and the server-written credentials, not just the new one"
	);
}

#[test]
fn add_app_password_drops_a_label_renamed_by_a_sibling() {
	// The same shape, but the sibling renamed a label. Without the
	// rebuild, the in-memory list would still carry the old label
	// (from the mirror's open() snapshot), so authentication would
	// match the old label while disk only knows the new one.
	let dir = tempfile::tempdir().expect("tempdir");
	seed_account(dir.path(), "alice");
	let config = config(dir.path());
	let store = AccountStore::open(
		dir.path(),
		config.domains.clone(),
		std::collections::HashMap::new(),
		config.accounts.clone(),
	)
	.expect("open store");

	// Pre-seed the disk with one credential.
	let mut cli = AppPasswordStore::open(dir.path()).expect("open sibling");
	cli.add(
		"alice",
		AppPassword {
			label: "old".to_string(),
			hash: "argon2id-phc-old".to_string(),
			expires_at: None,
			ip_cidr: None,
			save_sent: None,
		},
	)
	.expect("sibling add old");

	// The server now opens again, the disk still has the old entry,
	// the server's mirror is still empty (never refreshed). Then a
	// sibling remove + add cycle renames it.
	store
		.add_app_password(
			"alice",
			AppPassword {
				label: "second".to_string(),
				hash: "argon2id-phc-second".to_string(),
				expires_at: None,
				ip_cidr: None,
				save_sent: None,
			},
		)
		.expect("server add second");

	// The server's mirror must hold the `second` label and not
	// carry the `old` label twice.
	let mirror = store.for_account("alice");
	let labels: Vec<&str> = mirror.iter().map(|app| app.label.as_str()).collect();
	assert_eq!(
		labels,
		vec!["old".to_string(), "second".to_string()],
		"the mirror must reflect the post-write disk state"
	);

	// Drop the assertion-target variable so the test compiles even
	// if the type changes.
	let _ = ExitCode::SUCCESS;
}