//! The real CLI must distinguish an unresolved owner from a server-owned one.

use super::*;
use crate::storage::rekey::tests::fixture::{Fixture, fixture};
use std::path::PathBuf;

const SQL: &str = "[database]\nurl = 'postgres://fixture:fixture@127.0.0.1/epistle?sslmode=require'\ndirectory = true\n";
const LDAP: &str = "[ldap]\nurl = 'ldap://directory.example.org'\nbind_dn = 'cn=fixture'\nbind_password = 'fixture'\nbase_dn = 'dc=example,dc=org'\nuser_filter = '(uid=%s)'\n";

pub(super) fn config(fx: &Fixture, source: &str, known: bool, tenant_key: bool) -> PathBuf {
	let account = if known {
		"[[accounts]]\nname = 'alice'\naddresses = ['alice@acme.test']\n"
	} else {
		""
	};
	let tenant = if tenant_key {
		format!(
			"[[tenant]]\nname = 'acme'\ndomains = ['acme.test']\nencryption_key_file = {:?}\n",
			fx.data_dir().join("acme.key")
		)
	} else {
		String::new()
	};
	let path = fx.data_dir().join("mail.toml");
	std::fs::write(&path, format!("hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['acme.test']\n{account}[storage]\nencrypt_at_rest = true\ntenant_keys = {tenant_key}\nencryption_key_file = {:?}\n{tenant}{source}", fx.data_dir(), fx.data_dir().join("server.key"))).unwrap();
	std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	Config::load(&path).expect("valid production configuration");
	path
}

pub(super) fn invoke(path: &Path, rollback: bool, dry_run: bool) -> (ExitCode, String) {
	let mut status = Vec::new();
	let code = run(
		path,
		TenantKeysCli::Migrate { rollback },
		dry_run,
		false,
		&mut Vec::new(),
		&mut status,
	);
	(code, String::from_utf8(status).unwrap())
}

fn unresolved(source: &str, tenant_envelope: bool) {
	let fx = fixture();
	let bytes = if tenant_envelope {
		fx.crypto_writing(true)
			.seal_for(&KeyOwner::Tenant("acme".into()), b"private tenant mail")
			.unwrap()
	} else {
		fx.server_only().encode(b"legacy mail").unwrap()
	};
	let mail = fx.write_raw("alice", "new/one.eml", &bytes);
	let path = config(&fx, source, false, true);
	let (code, status) = invoke(&path, false, false);
	assert_eq!(
		code,
		ExitCode::FAILURE,
		"an unresolved directory owner must not become server-owned: {status}"
	);
	assert!(
		status.contains("cannot resolve owner") && status.contains("alice"),
		"{status}"
	);
	assert_eq!(
		std::fs::read(&mail).unwrap(),
		bytes,
		"unknown-owner mail must remain untouched"
	);
	assert_eq!(fx.files(), [mail], "no replacement temporary may be left");
	assert_eq!(journal::read(fx.data_dir()).unwrap(), None);
}

#[test]
fn tk03_unresolved_sql_owner_is_refused_for_legacy_mail() {
	unresolved(SQL, false);
}
#[test]
fn tk03_unresolved_sql_owner_is_refused_for_tenant_mail() {
	unresolved(SQL, true);
}
#[test]
fn tk03_unresolved_ldap_owner_is_refused_for_legacy_mail() {
	unresolved(LDAP, false);
}
#[test]
fn tk03_unresolved_ldap_owner_is_refused_for_tenant_mail() {
	unresolved(LDAP, true);
}

#[test]
fn tk03_resolved_file_owner_uses_its_tenant_key() {
	let fx = fixture();
	let mail = fx.store("alice", "new/one.eml", b"private");
	let path = config(&fx, LDAP, true, true);
	let (code, status) = invoke(&path, false, false);
	assert_eq!(code, ExitCode::SUCCESS, "{status}");
	let stored = std::fs::read(mail).unwrap();
	assert_eq!(
		fx.crypto().open_owned(&stored).unwrap(),
		(b"private".to_vec(), KeyOwner::Tenant("acme".into()))
	);
	assert!(fx.server_only().decode(&stored).is_err());
}

#[test]
fn tk03_resolved_file_owner_can_rotate_without_tenant_keys() {
	let fx = fixture();
	let mail = fx.store("alice", "new/one.eml", b"server owned");
	let path = config(&fx, "", true, false);
	let (code, status) = invoke(&path, false, false);
	assert_eq!(code, ExitCode::SUCCESS, "{status}");
	assert_eq!(
		fx.server_only()
			.decode(&std::fs::read(mail).unwrap())
			.unwrap(),
		b"server owned"
	);
}
