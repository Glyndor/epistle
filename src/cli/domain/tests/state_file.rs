//! `epistle domain` writes `<data_dir>/domains.toml` and leaves the
//! configuration file alone, including the per-domain limits of `domain set`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use super::run;
use super::{DomainAliasArgs, DomainAliasSubcommand, DomainCli};
use crate::config::Config;
use crate::domain::state::{DomainsFile, StoredRole};

struct Fixture {
	_dir: tempfile::TempDir,
	config: PathBuf,
	data_dir: PathBuf,
}

impl Fixture {
	fn new(extra: &str) -> Self {
		let dir = tempfile::tempdir().unwrap();
		let data_dir = dir.path().canonicalize().unwrap();
		let config = data_dir.join("mail.toml");
		let mut file = std::fs::File::create(&config).unwrap();
		writeln!(
			file,
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\n\
			 domains = [\"example.org\", \"other.example.org\"]\n{extra}",
			data_dir.to_string_lossy()
		)
		.unwrap();
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
		}
		Fixture {
			_dir: dir,
			config,
			data_dir,
		}
	}

	fn run(&self, action: DomainCli) -> ExitCode {
		run(&self.config, action, false, false)
	}

	fn state(&self) -> Option<DomainsFile> {
		DomainsFile::read(&crate::domain::state::path(&self.data_dir)).unwrap()
	}

	fn mail_toml(&self) -> String {
		std::fs::read_to_string(&self.config).unwrap()
	}

	fn loaded(&self) -> Config {
		Config::load(&self.config).expect("the configuration loads")
	}
}

fn add(domain: &str) -> DomainCli {
	DomainCli::Add {
		domain: domain.into(),
		shared_dkim_key: false,
		send_only: false,
		receive_only: false,
	}
}

#[test]
fn add_writes_the_state_file_and_not_the_configuration_file() {
	let fixture = Fixture::new("");
	let before = fixture.mail_toml();
	assert_eq!(fixture.run(add("New.Example.org")), ExitCode::SUCCESS);
	assert_eq!(fixture.mail_toml(), before, "mail.toml is not written");
	let state = fixture.state().expect("the state file exists");
	assert_eq!(
		state.names(),
		["example.org", "other.example.org", "new.example.org"],
		"seeded from mail.toml, then the new domain stored lowercase"
	);
	let added = state.domain("new.example.org").unwrap();
	assert!(added.srs_secret.is_some(), "the domain gets an SRS secret");
	assert!(added.enabled);
	assert!(
		fixture
			.loaded()
			.domains
			.iter()
			.any(|d| d == "new.example.org"),
		"the next load hosts it"
	);
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let mode = std::fs::metadata(crate::domain::state::path(&fixture.data_dir))
			.unwrap()
			.permissions()
			.mode();
		assert_eq!(mode & 0o777, 0o600, "the file holds a secret");
	}
}

#[test]
fn a_dry_run_writes_nothing_at_all() {
	let fixture = Fixture::new("");
	let before = fixture.mail_toml();
	assert_eq!(
		run(&fixture.config, add("new.example.org"), true, false),
		ExitCode::SUCCESS
	);
	assert!(fixture.state().is_none(), "no state file is made");
	assert_eq!(fixture.mail_toml(), before);
	assert!(
		!fixture.data_dir.join("keys").exists(),
		"no key is made either"
	);
}

#[test]
fn remove_enable_disable_set_and_aliases_go_to_the_state_file() {
	let fixture = Fixture::new("[[listeners]]\nkind = \"smtp\"\nport = 2525\n");
	let before = fixture.mail_toml();
	let alias = |action| DomainCli::Alias(DomainAliasArgs { action });
	let steps = [
		DomainCli::Disable {
			domain: "other.example.org".into(),
			yes: true,
		},
		DomainCli::Set {
			domain: "example.org".into(),
			quota: None,
			no_quota: false,
			submission_rate: None,
			no_submission_rate: false,
			send_only: true,
			receive_only: false,
			full: false,
		},
		alias(DomainAliasSubcommand::Add {
			alias: "Alias.Example.net".into(),
			target: "example.org".into(),
		}),
	];
	for step in steps {
		assert_eq!(fixture.run(step), ExitCode::SUCCESS);
	}
	let state = fixture.state().unwrap();
	assert!(!state.domain("other.example.org").unwrap().enabled);
	assert_eq!(
		state.domain("example.org").unwrap().role,
		StoredRole::SendOnly
	);
	assert_eq!(
		state.aliases.get("alias.example.net").map(String::as_str),
		Some("example.org")
	);
	let loaded = fixture.loaded();
	assert_eq!(loaded.disabled_domains, ["other.example.org"]);
	assert_eq!(loaded.send_only_domains, ["example.org"]);
	for step in [
		alias(DomainAliasSubcommand::Remove {
			alias: "alias.example.net".into(),
			yes: true,
		}),
		DomainCli::Enable {
			domain: "other.example.org".into(),
		},
		DomainCli::Remove {
			domain: "other.example.org".into(),
			yes: true,
		},
	] {
		assert_eq!(fixture.run(step), ExitCode::SUCCESS);
	}
	let state = fixture.state().unwrap();
	assert_eq!(state.names(), ["example.org"]);
	assert!(state.aliases.is_empty());
	assert_eq!(fixture.mail_toml(), before, "mail.toml is never written");
}

#[test]
fn the_last_enabled_domain_is_a_policy_refusal_and_nothing_changes() {
	let fixture = Fixture::new("[[listeners]]\nkind = \"smtp\"\nport = 2525\n");
	assert_eq!(
		fixture.run(DomainCli::Disable {
			domain: "other.example.org".into(),
			yes: true,
		}),
		ExitCode::SUCCESS
	);
	let before = fixture.state();
	let code = fixture.run(DomainCli::Disable {
		domain: "example.org".into(),
		yes: true,
	});
	assert_eq!(code, ExitCode::from(crate::cli::exit::POLICY));
	assert_eq!(fixture.state(), before);
}

#[test]
fn the_quota_and_role_of_set_share_the_state_file() {
	let fixture = Fixture::new("");
	let before = fixture.mail_toml();
	let code = fixture.run(DomainCli::Set {
		domain: "example.org".into(),
		quota: Some("1G".into()),
		no_quota: false,
		submission_rate: None,
		no_submission_rate: false,
		send_only: false,
		receive_only: true,
		full: false,
	});
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(fixture.mail_toml(), before);
	assert_eq!(
		fixture.loaded().domain_quotas["example.org"],
		1024_u64.pow(3)
	);
	assert!(
		!fixture.mail_toml().contains("receive_only_domains"),
		"the role is not written to mail.toml"
	);
	assert_eq!(
		fixture.state().unwrap().domain("example.org").unwrap().role,
		StoredRole::ReceiveOnly
	);
}

#[test]
fn hostile_names_are_refused_before_anything_is_written() {
	let fixture = Fixture::new("");
	for name in [
		"example.org.",
		"bücher.example",
		"exa mple.org",
		"",
		"раураl.com",
		"-bad.example.org",
	] {
		assert_eq!(
			fixture.run(add(name)),
			ExitCode::FAILURE,
			"{name:?} is refused"
		);
	}
	assert!(fixture.state().is_none(), "nothing was written");
	assert_eq!(
		fixture.run(add("EXAMPLE.ORG")),
		ExitCode::FAILURE,
		"a hosted domain in another case is already configured"
	);
}

#[test]
fn import_takes_the_configuration_file_lists_again() {
	let fixture = Fixture::new("");
	assert_eq!(fixture.run(add("new.example.org")), ExitCode::SUCCESS);
	let code = fixture.run(DomainCli::Import { yes: true });
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(
		fixture.state().unwrap().names(),
		["example.org", "other.example.org"]
	);
}

#[test]
fn import_replaces_a_state_file_that_does_not_parse_and_keeps_it_aside() {
	let fixture = Fixture::new("");
	let path = crate::domain::state::path(&fixture.data_dir);
	std::fs::write(&path, "[[domain]\nname = ").unwrap();
	assert!(
		Config::load(&fixture.config).is_err(),
		"a broken file stops the load"
	);
	assert_eq!(
		fixture.run(DomainCli::Import { yes: true }),
		ExitCode::SUCCESS
	);
	assert!(Path::new(&path.with_extension("toml.bad")).exists());
	assert_eq!(
		fixture.state().unwrap().names(),
		["example.org", "other.example.org"]
	);
}
