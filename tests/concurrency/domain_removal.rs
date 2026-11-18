//! Removing a hosted domain while an account is created on it. The removal
//! decides under the lock of `domains.toml`; the account must be admitted by
//! that file, under the same lock, and not by the snapshot the running server
//! holds until its watcher reloads.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

use epistle::config::Config;
use epistle::directory_store::{AccountStore, DynamicAccount, StoreError};
use epistle::domain::state::DomainsFile;
use epistle::domain::state::edit::{Change, EditError, commit, commit_checked, seed};

const KEPT: &str = "example.org";
const REMOVED: &str = "other.example.org";

/// A data directory hosting [`KEPT`] and [`REMOVED`], the state file seeded
/// from the configuration the way `serve` does, and a store opened on them
/// (which keeps that snapshot of the domains).
struct Hosting {
	_dir: tempfile::TempDir,
	data_dir: PathBuf,
	config: Config,
	store: Arc<AccountStore>,
}

fn hosting() -> Hosting {
	let dir = tempfile::tempdir().expect("data dir");
	let data_dir = dir.path().canonicalize().expect("canonical data dir");
	let path = data_dir.join("mail.toml");
	std::fs::write(
		&path,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"{KEPT}\", \"{REMOVED}\"]\n",
			data_dir.to_string_lossy()
		),
	)
	.expect("write the configuration");
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	}
	let config = Config::load(&path).expect("the configuration loads");
	assert!(seed(&config).expect("seed the state file"));
	let store = AccountStore::open(
		&data_dir,
		vec![KEPT.into(), REMOVED.into()],
		HashMap::new(),
		vec![],
	)
	.expect("open the store");
	Hosting {
		_dir: dir,
		data_dir,
		config,
		store: Arc::new(store),
	}
}

fn account(name: &str, address: &str) -> DynamicAccount {
	DynamicAccount {
		name: name.into(),
		addresses: vec![address.into()],
		password_hash: "$argon2id$stub".into(),
		..DynamicAccount::default()
	}
}

fn remove() -> Change {
	Change::Remove {
		name: REMOVED.into(),
	}
}

fn still_hosted(data_dir: &Path) -> bool {
	DomainsFile::read(&epistle::domain::state::path(data_dir))
		.expect("read the state file")
		.expect("the state file exists")
		.domain(REMOVED)
		.is_some()
}

fn has_account_on_removed(data_dir: &Path) -> bool {
	std::fs::read_to_string(data_dir.join("accounts.toml"))
		.is_ok_and(|text| text.contains(&format!("@{REMOVED}")))
}

/// The longer window: the removal answered, the watcher has not reloaded, so
/// the running store still lists the domain.
#[test]
fn an_account_is_refused_on_a_domain_removed_before_the_watcher_reloaded() {
	let hosting = hosting();
	commit(&hosting.config, &remove()).expect("remove the unused domain");
	assert!(
		hosting
			.store
			.hosted_domains()
			.domains
			.iter()
			.any(|d| d == REMOVED),
		"the snapshot is stale, as it is until the watcher reloads"
	);
	let refused = hosting
		.store
		.add(account("late", &format!("late@{REMOVED}")))
		.expect_err("the domain is no longer hosted");
	assert!(matches!(refused, StoreError::Invalid(_)), "{refused:?}");
	assert!(!has_account_on_removed(&hosting.data_dir));
}

/// The same for an address added to an account that already exists.
#[test]
fn an_address_is_refused_on_a_domain_removed_before_the_watcher_reloaded() {
	let hosting = hosting();
	hosting
		.store
		.add(account("early", &format!("early@{KEPT}")))
		.expect("add on the kept domain");
	commit(&hosting.config, &remove()).expect("remove the unused domain");
	let refused = hosting
		.store
		.add_address("early", &format!("second@{REMOVED}"))
		.expect_err("the domain is no longer hosted");
	assert!(matches!(refused, StoreError::Invalid(_)), "{refused:?}");
	assert!(!has_account_on_removed(&hosting.data_dir));
}

/// The short window, with the order forced: the removal holds the lock of
/// `domains.toml` while the account is created, so the creation can only see
/// the file after the removal wrote it.
#[test]
fn a_creation_that_starts_while_a_removal_holds_the_lock_sees_the_removal() {
	let hosting = hosting();
	let inside = Arc::new(Barrier::new(2));
	let go = Arc::new(Barrier::new(2));
	let removal = {
		let config = hosting.config.clone();
		let (inside, go) = (Arc::clone(&inside), Arc::clone(&go));
		std::thread::spawn(move || {
			commit_checked(&config, &remove(), |_, _| {
				inside.wait();
				go.wait();
				Ok(())
			})
		})
	};
	inside.wait();
	let creation = {
		let store = Arc::clone(&hosting.store);
		std::thread::spawn(move || store.add(account("raced", &format!("raced@{REMOVED}"))))
	};
	go.wait();
	removal
		.join()
		.expect("removal thread")
		.expect("no account existed when the removal checked, so it removes");
	let refused = creation.join().expect("creation thread");
	assert!(
		matches!(refused, Err(StoreError::Invalid(_))),
		"{refused:?}"
	);
	assert!(!still_hosted(&hosting.data_dir));
	assert!(!has_account_on_removed(&hosting.data_dir));
}

/// Many rounds of both starting from one barrier: whichever goes first, one of
/// them is refused and the state never holds an account on a domain the file
/// no longer hosts.
#[test]
fn a_removal_and_a_creation_started_together_never_cross() {
	for round in 0..40 {
		let hosting = hosting();
		let start = Arc::new(Barrier::new(2));
		let removal = {
			let config = hosting.config.clone();
			let start = Arc::clone(&start);
			std::thread::spawn(move || {
				start.wait();
				commit(&config, &remove())
			})
		};
		let creation = {
			let store = Arc::clone(&hosting.store);
			let start = Arc::clone(&start);
			std::thread::spawn(move || {
				start.wait();
				store.add(account("raced", &format!("raced@{REMOVED}")))
			})
		};
		let removed = removal.join().expect("removal thread");
		let created = creation.join().expect("creation thread");
		let crossed = has_account_on_removed(&hosting.data_dir) && !still_hosted(&hosting.data_dir);
		assert!(
			!crossed,
			"round {round}: an account is on {REMOVED}, which is no longer hosted"
		);
		match (removed, created) {
			(Ok(_), Err(StoreError::Invalid(_))) | (Err(EditError::InUse(_)), Ok(())) => {}
			(removed, created) => panic!(
				"round {round}: exactly one of them must win; removal: {removed:?}, creation: {created:?}"
			),
		}
	}
}
