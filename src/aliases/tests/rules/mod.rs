//! The rules for the operator and for a key of the API, and the attacks a key
//! can try: another tenant's domain, a member that is not local or not in the
//! key's domains, an address that collides, a role address, odd spellings and
//! the sizes.

use crate::aliases::edit::{self, NewAlias, rules::MAX_MEMBERS};
use crate::aliases::{AliasError, Change, Origin};
use crate::config::Config;

mod members;
mod reach;
mod roles;
mod scope;

/// Two domains, two accounts in the first and one in the second.
pub(super) fn setup(extra: &str) -> (tempfile::TempDir, Config) {
	let dir = tempfile::tempdir().expect("dir");
	let data = dir.path().join("data");
	std::fs::create_dir(&data).expect("data dir");
	let data = data.canonicalize().expect("canonical");
	std::fs::write(
		data.join("accounts.toml"),
		"[[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\npassword_hash = \"stub\"\n\n\
		 [[accounts]]\nname = \"bob\"\naddresses = [\"bob@example.org\"]\npassword_hash = \"stub\"\n\n\
		 [[accounts]]\nname = \"carol\"\naddresses = [\"carol@example.net\"]\npassword_hash = \"stub\"\n",
	)
	.expect("accounts");
	let file = dir.path().join("mail.toml");
	std::fs::write(
		&file,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = {data:?}\n\
			 domains = [\"example.org\", \"example.net\"]\n\
			 [domain_aliases]\n\"alias.example.org\" = \"example.org\"\n{extra}\n"
		),
	)
	.expect("config");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	}
	let config = Config::load(&file).expect("loads");
	(dir, config)
}

pub(super) fn new(address: &str, members: &[&str]) -> Change {
	Change::Add(NewAlias {
		address: address.into(),
		members: members.iter().map(|member| member.to_string()).collect(),
		senders: Vec::new(),
		list_id: None,
		hidden: true,
	})
}

pub(super) fn key(domains: Option<&[&str]>) -> Origin {
	Origin::Api {
		confined_to: domains.map(|list| list.iter().map(|d| d.to_string()).collect()),
	}
}

pub(super) fn refused(config: &Config, change: &Change, origin: &Origin) -> AliasError {
	edit::preview(config, change, origin).expect_err("refused")
}

pub(super) fn operator_made(config: &Config, address: &str, members: &[&str]) {
	edit::commit(config, &new(address, members), &Origin::Operator).expect("operator");
}
