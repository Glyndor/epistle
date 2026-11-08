//! A completed journal row is only a hint: keys and mail can change between runs.

use super::base::{Cut, call, options};
use super::*;
use crate::config::{Storage, Tenant};
use crate::storage::AccountAddresses;
use crate::storage::rekey::tests::fixture::{Fixture, fixture};
use std::sync::Arc;

struct Addresses;
impl AccountAddresses for Addresses {
	fn addresses_for(&self, account: &str) -> Vec<String> {
		vec![format!("{account}@acme.test")]
	}
}

fn crypto(fx: &Fixture, server: &str, retired: &[&str], tenant: Option<&str>) -> MessageCrypto {
	let storage = Storage {
		encrypt_at_rest: true,
		tenant_keys: tenant.is_some(),
		encryption_key_file: Some(fx.data_dir().join(format!("{server}.key"))),
		retired_key_files: retired
			.iter()
			.map(|name| fx.data_dir().join(format!("{name}.key")))
			.collect(),
		..Storage::default()
	};
	let tenants: Vec<Tenant> = tenant
		.into_iter()
		.map(|key| {
			toml::from_str(&format!(
				"name = 'acme'\ndomains = ['acme.test']\nencryption_key_file = {:?}",
				fx.data_dir().join(format!("{key}.key"))
			))
			.unwrap()
		})
		.collect();
	let crypto = MessageCrypto::from_parts(Some(&storage), &tenants).unwrap();
	crypto.attach_accounts(Arc::new(Addresses));
	crypto
}

fn completed_alice(fx: &Fixture) {
	let mut progress = Journal::new(Direction::Forward);
	progress.done.push("alice".into());
	journal::write(fx.data_dir(), &progress).unwrap();
}

#[test]
fn tk01_resume_rescans_completed_accounts_for_mail_added_after_a_cut() {
	let fx = fixture();
	let crypto = fx.crypto_writing(true);
	fx.store("alice", "new/one.eml", b"one");
	let bob = crypto
		.seal_for(&KeyOwner::Tenant("acme".into()), b"bob")
		.unwrap();
	fx.write_raw("bob", "new/two.eml", &bob);
	let (code, _, status) = call(&fx, &crypto, &options(Direction::Forward), &mut Cut(1));
	assert_eq!(code, ExitCode::FAILURE);
	assert!(status.contains("bob: power cut"), "{status}");
	assert_eq!(
		journal::read(fx.data_dir()).unwrap().unwrap().done,
		["alice"]
	);
	let late = fx.store("alice", "new/late.eml", b"late");
	let (code, _, status) = call(
		&fx,
		&crypto,
		&options(Direction::Forward),
		&mut rekey::NoHooks,
	);
	assert_eq!(code, ExitCode::SUCCESS, "{status}");
	let stored = std::fs::read(late).unwrap();
	assert_eq!(
		crypto.open_owned(&stored).unwrap(),
		(b"late".to_vec(), KeyOwner::Tenant("acme".into()))
	);
	assert!(
		fx.server_only().decode(&stored).is_err(),
		"late mail must leave the server key"
	);
}

#[test]
fn tk01_resume_rechecks_completed_accounts_after_server_key_rotation() {
	let fx = fixture();
	let alice = fx.store("alice", "new/one.eml", b"alice");
	fx.store("bob", "new/two.eml", b"bob");
	completed_alice(&fx);
	let next = crypto(&fx, "globex", &["server"], None);
	let (code, _, status) = call(
		&fx,
		&next,
		&options(Direction::Forward),
		&mut rekey::NoHooks,
	);
	assert_eq!(code, ExitCode::SUCCESS, "{status}");
	let current_only = crypto(&fx, "globex", &[], None);
	assert_eq!(
		current_only
			.decode(&std::fs::read(alice).unwrap())
			.expect("completed Alice must read after K1 is removed"),
		b"alice"
	);
}

#[test]
fn tk01_resume_rechecks_completed_accounts_after_tenant_key_rotation() {
	let fx = fixture();
	let first = fx.crypto_writing(true);
	let stored = first
		.seal_for(&KeyOwner::Tenant("acme".into()), b"alice")
		.unwrap();
	let alice = fx.write_raw("alice", "new/one.eml", &stored);
	completed_alice(&fx);
	let next = crypto(&fx, "server", &["acme"], Some("globex"));
	let (code, _, status) = call(
		&fx,
		&next,
		&options(Direction::Forward),
		&mut rekey::NoHooks,
	);
	assert_eq!(code, ExitCode::SUCCESS, "{status}");
	let current_only = crypto(&fx, "server", &[], Some("globex"));
	assert_eq!(
		current_only
			.decode(&std::fs::read(alice).unwrap())
			.expect("completed Alice must read after T1 is removed"),
		b"alice"
	);
}
