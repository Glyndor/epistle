//! Store exclusion must precede journal reads and survive every replacement.

use super::base::{call, options};
use super::*;
use crate::storage::lock::FileLock;
use crate::storage::rekey::tests::fixture::fixture;

#[test]
fn tk02_migration_refuses_a_store_holder_without_touching_mail_or_journal() {
	let fx = fixture();
	let path = fx.store("alice", "new/one.eml", b"one");
	let before = std::fs::read(&path).unwrap();
	let _holder = FileLock::acquire(&fx.data_dir().join(".store.lock")).unwrap();
	let (code, _, status) = call(
		&fx,
		&fx.crypto_writing(true),
		&options(Direction::Forward),
		&mut rekey::NoHooks,
	);
	assert_eq!(
		code,
		ExitCode::FAILURE,
		"a store holder must exclude migration: {status}"
	);
	assert!(status.contains("store is in use"), "{status}");
	assert_eq!(std::fs::read(path).unwrap(), before);
	assert_eq!(journal::read(fx.data_dir()).unwrap(), None);
}

struct Contender<'a>(&'a Path, &'a MessageCrypto);
impl Hooks for Contender<'_> {
	fn before_replace(&mut self, original: &Path) -> std::io::Result<()> {
		assert!(
			FileLock::try_acquire(&self.0.join(".store.lock"))?.is_none(),
			"migration released its lock before replacing mail"
		);
		let before = std::fs::read(original)?;
		let mut status = Vec::new();
		let code = migrate(
			self.0,
			self.1,
			&options(Direction::Forward),
			&mut rekey::NoHooks,
			&mut Vec::new(),
			&mut status,
		);
		assert_eq!(
			code,
			ExitCode::FAILURE,
			"a competing migration must be refused"
		);
		assert!(String::from_utf8_lossy(&status).contains("store is in use"));
		assert_eq!(std::fs::read(original)?, before);
		Ok(())
	}
}

#[test]
fn tk02_migration_holds_exclusion_through_replacement() {
	let fx = fixture();
	fx.store("alice", "new/one.eml", b"one");
	let crypto = fx.crypto_writing(true);
	let (code, _, status) = call(
		&fx,
		&crypto,
		&options(Direction::Forward),
		&mut Contender(fx.data_dir(), &crypto),
	);
	assert_eq!(code, ExitCode::SUCCESS, "{status}");
	assert!(
		FileLock::try_acquire(&fx.data_dir().join(".store.lock"))
			.unwrap()
			.is_some(),
		"lock released after completion"
	);
}

#[test]
fn tk02_offline_import_refuses_migration_before_writing() {
	use clap::Parser;
	let fx = fixture();
	let source = fx.data_dir().join("maildir");
	std::fs::create_dir_all(source.join("new")).unwrap();
	std::fs::write(source.join("new/message"), b"Subject: import\r\n\r\nbody").unwrap();
	let config = fx.data_dir().join("mail.toml");
	std::fs::write(
		&config,
		format!(
			"hostname = 'mail.example.org'\ndata_dir = {:?}",
			fx.data_dir()
		),
	)
	.unwrap();
	std::fs::set_permissions(&config, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	Config::load(&config).expect("valid import config");
	let _migration = FileLock::acquire(&fx.data_dir().join(".store.lock")).unwrap();
	let command = crate::cli::Cli::try_parse_from([
		"epistle",
		"import",
		"--config",
		config.to_str().unwrap(),
		"--account",
		"alice",
		"--maildir",
		source.to_str().unwrap(),
	])
	.unwrap();
	assert_eq!(
		command.run(),
		ExitCode::FAILURE,
		"offline import must refuse migration"
	);
	assert!(
		!fx.data_dir().join("accounts/alice").exists(),
		"no imported mail may race migration"
	);
}

#[test]
fn tk02_cli_entry_refuses_a_store_holder() {
	let fx = fixture();
	let path = fx.store("alice", "new/one.eml", b"one");
	let before = std::fs::read(&path).unwrap();
	let config = fx.data_dir().join("mail.toml");
	std::fs::write(&config, format!("hostname = 'mail.example.org'\ndata_dir = {:?}\n[storage]\nencrypt_at_rest = true\nencryption_key_file = {:?}", fx.data_dir(), fx.data_dir().join("server.key"))).unwrap();
	std::fs::set_permissions(&config, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	Config::load(&config).expect("valid migration config");
	let _holder = FileLock::acquire(&fx.data_dir().join(".store.lock")).unwrap();
	let mut status = Vec::new();
	let code = run(
		&config,
		TenantKeysCli::Migrate { rollback: false },
		false,
		false,
		&mut Vec::new(),
		&mut status,
	);
	assert_eq!(
		code,
		ExitCode::FAILURE,
		"the real CLI entry must hold the store lock"
	);
	assert!(String::from_utf8_lossy(&status).contains("store is in use"));
	assert_eq!(std::fs::read(path).unwrap(), before);
}
