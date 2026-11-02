//! How `--finish` removes a record: by exact value, every value of the shared
//! key at the name, nothing else, and it looks again afterwards.

use std::process::ExitCode;
use std::sync::Arc;

use super::finish::{FINISH, shared_value, split_install, switched_days_ago};
use super::harness::{Flaw, Flawed, Provider, Resolver, run, run_with};
use crate::dns::provider::DnsProvider;

fn flawed(zone: &super::harness::Zone, flaw: Flaw) -> Option<Arc<dyn DnsProvider>> {
	Some(Arc::new(Flawed {
		zone: zone.clone(),
		flaw,
	}))
}

fn resolver(zone: &super::harness::Zone) -> Resolver {
	Resolver {
		zone: zone.clone(),
		blind: false,
	}
}

#[test]
fn a_provider_that_cannot_match_by_value_is_not_asked_to_delete_and_the_record_is_listed() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	let before = zone.published();
	let (code, out, _, _) = run_with(
		&install,
		&FINISH,
		flawed(&zone, Flaw::NoExactDelete),
		&resolver(&zone),
		false,
	);
	assert_eq!(code, ExitCode::SUCCESS, "{out}");
	assert!(zone.deleted.lock().unwrap().is_empty());
	assert_eq!(zone.published(), before);
	assert!(
		out.contains("remove by hand")
			&& out.contains("s1._domainkey.b.example.org")
			&& out.contains(&shared_value(&install)),
		"{out}"
	);
}

#[test]
fn every_value_of_the_shared_key_at_a_name_goes_and_a_foreign_one_stays() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	let shared = shared_value(&install);
	let p = shared.rsplit("p=").next().expect("p").to_string();
	let variant = format!("v=DKIM1;k=ed25519;p={p}");
	let (_, foreign) = crate::dkim::generate_key().expect("key");
	zone.records.lock().unwrap().insert(
		"s1._domainkey.b.example.org".into(),
		vec![shared.clone(), variant.clone(), foreign.clone()],
	);
	let (code, out, err, _) = run(
		&install,
		&FINISH,
		Some(Provider {
			zone: zone.clone(),
			refuses: false,
		}),
		&resolver(&zone),
	);
	assert_eq!(code, ExitCode::SUCCESS, "{out}\n{err}");
	let deleted = zone.deleted.lock().unwrap().clone();
	for value in [&shared, &variant] {
		assert!(
			deleted.contains(&("s1._domainkey.b.example.org".to_string(), value.clone())),
			"{deleted:?}"
		);
	}
	assert_eq!(
		zone.records.lock().unwrap()["s1._domainkey.b.example.org"],
		[foreign],
		"only the record that is not ours is left"
	);
}

#[test]
fn a_provider_that_wipes_the_whole_name_is_caught_by_the_second_look() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	let (_, foreign) = crate::dkim::generate_key().expect("key");
	zone.records
		.lock()
		.unwrap()
		.get_mut("s1._domainkey.b.example.org")
		.expect("name")
		.push(foreign);
	let (code, _, err, _) = run_with(
		&install,
		&FINISH,
		flawed(&zone, Flaw::Greedy),
		&resolver(&zone),
		false,
	);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(
		err.contains("a record that is not ours at s1._domainkey.b.example.org is gone"),
		"{err}"
	);
}

#[test]
fn a_delete_that_changes_nothing_is_a_failure_not_a_retirement() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	let (code, out, err, _) = run_with(
		&install,
		&FINISH,
		flawed(&zone, Flaw::Inert),
		&resolver(&zone),
		false,
	);
	assert_eq!(code, ExitCode::FAILURE, "{out}");
	assert!(err.contains("the shared key is still visible"), "{err}");
	assert!(!out.contains("retired TXT"), "{out}");
}

#[test]
fn a_record_at_a_name_whose_shared_key_is_not_on_this_host_is_unknown_not_ours() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	// A value that is not the shared key's and a shared key that cannot be read.
	let (_, other) = crate::dkim::generate_key().expect("key");
	zone.records
		.lock()
		.unwrap()
		.insert("s1._domainkey.b.example.org".into(), vec![other]);
	std::fs::remove_file(install.dir.path().join("default.pem")).expect("remove");
	let (code, _, err, _) = run_with(
		&install,
		&FINISH,
		flawed(&zone, Flaw::Greedy),
		&resolver(&zone),
		false,
	);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(err.contains("is not on this host"), "{err}");
	assert!(zone.deleted.lock().unwrap().is_empty());
}
