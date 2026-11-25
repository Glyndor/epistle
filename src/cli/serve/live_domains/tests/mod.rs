//! A change written by `epistle domain` reaches the running server through
//! the file watcher, with no restart: the directory, the DKIM signer and the
//! SRS keys all follow it.

use std::io::Write;
use std::sync::Arc;

use super::*;
use crate::directory_store::FileWatcher;
use crate::directory_store::file_watcher::{PollEvent, PollTarget, StateReloader};
use crate::domain::state::edit::add::{Signing, prepare};
use crate::domain::state::{Change, StoredRole, edit};

mod aliases;

struct Server {
	_dir: tempfile::TempDir,
	config: Config,
	store: Arc<AccountStore>,
	live: Arc<LiveConfig>,
	watcher: FileWatcher,
}

fn server(extra: &str) -> Server {
	let dir = tempfile::tempdir().unwrap();
	let data = dir.path().canonicalize().unwrap();
	let (pem, _) = crate::dkim::generate_key().unwrap();
	std::fs::write(data.join("default.pem"), pem).unwrap();
	let path = data.join("mail.toml");
	let mut file = std::fs::File::create(&path).unwrap();
	write!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {data:?}\ndomains = [\"example.org\"]\n\
		 [dkim]\nselector = \"s1\"\nkey_file = {:?}\n{extra}",
		data.join("default.pem")
	)
	.unwrap();
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	}
	let config = Config::load(&path).unwrap();
	let store = Arc::new(super::super::store::open_account_store(&config).unwrap());
	let live = start(&config);
	let watcher = FileWatcher::new(config.data_dir.clone(), Arc::clone(&store))
		.with_state(Arc::clone(&live) as Arc<dyn StateReloader>);
	Server {
		_dir: dir,
		config,
		store,
		live,
		watcher,
	}
}

fn add(config: &Config, name: &str) {
	let prepared = prepare(config, name, StoredRole::Full, (Signing::OwnKey, false), 1).unwrap();
	edit::commit(config, &prepared.change).unwrap();
}

fn reloaded(server: &mut Server) -> bool {
	server
		.watcher
		.poll()
		.events
		.contains(&PollEvent::Loaded(PollTarget::State(
			crate::domain::state::FILE_NAME,
		)))
}

#[test]
fn the_start_writes_the_state_file_from_the_configuration_file() {
	let server = server("");
	let path = crate::domain::state::path(&server.config.data_dir);
	let file = crate::domain::state::DomainsFile::read(&path)
		.unwrap()
		.unwrap();
	assert_eq!(file.names(), ["example.org"]);
	assert_eq!(server.live.current().domains, ["example.org"]);
}

#[test]
fn a_command_write_reaches_the_running_directory_without_a_restart() {
	let mut server = server("");
	follow(
		&server.live,
		Followers {
			account_store: Arc::clone(&server.store),
			signer: None,
			srs: crate::storage::SrsSlot::default(),
		},
	);
	let store = Arc::clone(&server.store);
	let directory = move || store.handle().current();
	assert!(!directory().hosts_domain("new.example"));
	add(&server.config, "New.Example");
	edit::commit(
		&server.config,
		&Change::AliasAdd {
			alias: "alias.example".into(),
			target: "example.org".into(),
		},
	)
	.unwrap();
	assert!(
		!directory().hosts_domain("new.example"),
		"not before the poll"
	);
	assert!(reloaded(&mut server));
	assert!(directory().hosts_domain("new.example"));
	assert!(directory().hosts_domain("alias.example"));
	edit::commit(
		&server.config,
		&Change::Remove {
			name: "new.example".into(),
		},
	)
	.unwrap();
	assert!(reloaded(&mut server));
	assert!(!directory().hosts_domain("new.example"));
}

#[test]
fn a_new_domain_signs_with_its_own_key_and_forwards_with_its_own_secret() {
	let mut server = server("");
	let signer = crate::dkim::PerDomainSigner::new(
		crate::dkim::ReloadableSigner::new(Arc::new(
			crate::dkim::Signer::load("s1", &server.config.data_dir.join("default.pem")).unwrap(),
		)),
		Vec::new(),
	);
	let srs = crate::storage::SrsSlot::default();
	follow(
		&server.live,
		Followers {
			account_store: Arc::clone(&server.store),
			signer: Some(signer.clone()),
			srs: srs.clone(),
		},
	);
	assert!(srs.current().is_none(), "SRS was off at start");
	add(&server.config, "new.example");
	assert!(reloaded(&mut server));
	let overrides = signer.overrides();
	assert_eq!(overrides.len(), 1);
	assert_eq!(overrides[0].domain, "new.example");
	assert!(
		srs.current().is_some(),
		"the new domain's secret switched SRS on"
	);
}

#[test]
fn a_bad_write_leaves_the_running_server_as_it_was() {
	let mut server = server("");
	follow(
		&server.live,
		Followers {
			account_store: Arc::clone(&server.store),
			signer: None,
			srs: crate::storage::SrsSlot::default(),
		},
	);
	let path = crate::domain::state::path(&server.config.data_dir);
	std::fs::write(&path, "[[domain]]\nname = \"bad name\"\n").unwrap();
	let report = server.watcher.poll();
	assert!(
		report
			.events
			.contains(&PollEvent::BadParse(PollTarget::State(
				crate::domain::state::FILE_NAME
			)))
	);
	assert_eq!(server.live.current().domains, ["example.org"]);
	assert!(server.store.handle().current().hosts_domain("example.org"));
}

#[test]
fn limits_installed_after_start_reach_the_directory_and_api_budget_through_the_watcher() {
	let mut server = server(
		"[[accounts]]\nname = 'alice'\naddresses = ['alice@example.org']\npassword_hash = '$argon2id$v=19$m=65536,t=2,p=1$YWFhYWFhYWFhYWFhYWFhYQ$0000000000000000000000000000000000000000000'\n",
	);
	follow(
		&server.live,
		Followers {
			account_store: Arc::clone(&server.store),
			signer: None,
			srs: crate::storage::SrsSlot::default(),
		},
	);
	let limiters = super::super::ratelimit::build_rate_limiters(&server.config);
	let state = crate::api::ApiState::new(
		&crate::api::api_keys::sha256_hash("watcher-limit-test"),
		server.config.data_dir.clone(),
		server.config.domains.clone(),
		Arc::clone(&server.store),
		crate::storage::FsSpool::open(&server.config.data_dir).unwrap(),
	)
	.with_directory(server.store.handle());
	let state = super::super::ratelimit::wire_api_submission_limits(
		state,
		&server.config,
		&limiters.send_limiter,
		&Arc::new(crate::api::TenantLimits::default()),
	);
	let dir = server.store.handle();
	assert_eq!(dir.current().quota_for("alice"), None);
	assert_eq!(dir.current().submission_limit_for("alice"), None);
	edit::commit(
		&server.config,
		&Change::Set {
			name: "example.org".into(),
			role: None,
			quota: Some(Some(42)),
			submission_rate: Some(Some(1)),
		},
	)
	.unwrap();
	assert_eq!(
		dir.current().quota_for("alice"),
		None,
		"not before the watcher"
	);
	assert!(reloaded(&mut server));
	assert_eq!(dir.current().quota_for("alice"), Some(42));
	assert_eq!(dir.current().submission_limit_for("alice"), Some(1));
	let _first = state.submission_budget("alice", &[]).charge(1, 1).unwrap();
	assert!(
		!state.submission_budget("alice", &[]).has_room(1),
		"the newly installed cap is enforced"
	);
	edit::commit(
		&server.config,
		&Change::Set {
			name: "example.org".into(),
			role: None,
			quota: Some(None),
			submission_rate: Some(None),
		},
	)
	.unwrap();
	assert!(reloaded(&mut server));
	assert_eq!(dir.current().quota_for("alice"), None);
	assert_eq!(dir.current().submission_limit_for("alice"), None);
	assert!(
		state.submission_budget("alice", &[]).has_room(1),
		"clearing the cap takes effect"
	);
}
