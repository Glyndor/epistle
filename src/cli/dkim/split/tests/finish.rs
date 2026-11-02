//! After a split the shared key is still published at the domains that left
//! it. The report names those records; `--finish` retires them once the
//! overlap has passed, only when they are shown to be the shared key's, and
//! never at the domain that kept the key.

use std::process::ExitCode;

use super::harness::{Failing, Install, Provider, Resolver, Zone, run, run_as};
use crate::cli::dkim::split::Options;

const SPLIT: Options = Options {
	dry_run: false,
	wait: 0,
	finish: false,
	skip_overlap_check: false,
	restarted: false,
};
pub(super) const FINISH: Options = Options {
	dry_run: false,
	wait: 0,
	finish: true,
	skip_overlap_check: false,
	restarted: false,
};

/// The record the shared key publishes.
pub(super) fn shared_value(install: &Install) -> String {
	crate::dkim::Signer::load("s1", &install.dir.path().join("default.pem"))
		.expect("loads")
		.dns_record_value()
}

/// A three-domain install that has been split, with the shared key's `s1`
/// record published at all three domains, as it is after a real split.
pub(super) fn split_install() -> (Install, Zone) {
	let install = Install::new(&["a.example.org", "b.example.org", "c.example.org"], "");
	let zone = Zone::default();
	for domain in ["a", "b", "c"] {
		zone.records.lock().unwrap().insert(
			format!("s1._domainkey.{domain}.example.org"),
			vec![shared_value(&install)],
		);
	}
	let (provider, resolver) = services(&zone);
	let (code, ..) = run(&install, &SPLIT, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS);
	(install, zone)
}

pub(super) fn services(zone: &Zone) -> (Provider, Resolver) {
	(
		Provider {
			zone: zone.clone(),
			refuses: false,
		},
		Resolver {
			zone: zone.clone(),
			blind: false,
		},
	)
}

/// Pretend the split happened, and the server was restarted onto it, `days`
/// days ago.
pub(super) fn switched_days_ago(install: &Install, days: u64) {
	let at = crate::cli::dkim::now_epoch() - days * 86_400;
	let file = install.data().join("dkim-split.json");
	let mut state: serde_json::Value =
		serde_json::from_str(&std::fs::read_to_string(&file).expect("state")).expect("json");
	for moved in state.as_object_mut().expect("object").values_mut() {
		moved["written"] = at.into();
		moved["restarted"] = at.into();
	}
	std::fs::write(file, state.to_string()).expect("write");
}

#[test]
fn the_split_report_lists_the_stale_records_of_every_moved_domain() {
	let install = Install::new(&["a.example.org", "b.example.org", "c.example.org"], "");
	let zone = Zone::default();
	let (provider, resolver) = services(&zone);
	let (code, out, _, _) = run_as(&install, &SPLIT, Some(provider), &resolver, true);
	assert_eq!(code, ExitCode::SUCCESS, "{out}");
	let result: serde_json::Value = serde_json::from_str(out.trim()).expect("json");
	let stale: Vec<_> = result["stale_records"]
		.as_array()
		.expect("stale_records")
		.iter()
		.map(|v| v.as_str().expect("name"))
		.collect();
	assert_eq!(
		stale,
		["s1._domainkey.b.example.org", "s1._domainkey.c.example.org"]
	);
}

#[test]
fn the_text_report_names_each_stale_record_in_full() {
	let install = Install::new(&["a.example.org", "b.example.org", "c.example.org"], "");
	let zone = Zone::default();
	let (provider, resolver) = services(&zone);
	let (_, out, _, _) = run(&install, &SPLIT, Some(provider), &resolver);
	for name in ["s1._domainkey.b.example.org", "s1._domainkey.c.example.org"] {
		assert!(
			out.contains(&format!("stale after the switch: {name} still publishes")),
			"{out}"
		);
	}
	assert!(!out.contains("s1._domainkey.a.example.org"), "{out}");
}

#[test]
fn the_split_records_when_it_wrote_and_when_the_server_was_restarted() {
	let (install, _) = split_install();
	let text = std::fs::read_to_string(install.data().join("dkim-split.json")).unwrap();
	let moments: serde_json::Value = serde_json::from_str(&text).unwrap();
	for domain in ["b.example.org", "c.example.org"] {
		assert!(moments[domain]["written"].as_u64().is_some());
		assert!(moments[domain]["restarted"].as_u64().is_some());
		assert!(
			moments[domain]["stale"]
				.as_array()
				.is_some_and(|stale| !stale.is_empty()),
			"the shared key's selectors are kept for --finish"
		);
	}
	assert!(moments.get("a.example.org").is_none());
}

#[test]
fn finish_waits_for_the_overlap_counted_from_the_switch() {
	let (install, zone) = split_install();
	let before = zone.published();
	let (provider, resolver) = services(&zone);
	let (code, _, err, _) = run(&install, &FINISH, Some(provider), &resolver);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(
		err.contains("s1._domainkey.b.example.org: not before"),
		"{err}"
	);
	assert_eq!(zone.published(), before, "nothing was removed");
	assert!(zone.deleted.lock().unwrap().is_empty());
}

#[test]
fn an_old_key_file_does_not_start_the_clock_early() {
	let (install, zone) = split_install();
	let old = std::time::SystemTime::now() - std::time::Duration::from_secs(400 * 86_400);
	for domain in ["b.example.org", "c.example.org"] {
		let file = install
			.data()
			.join("keys/dkim")
			.join(domain)
			.join("ed25519.pem");
		std::fs::File::options()
			.write(true)
			.open(file)
			.unwrap()
			.set_modified(old)
			.unwrap();
	}
	let (provider, resolver) = services(&zone);
	let (code, ..) = run(&install, &FINISH, Some(provider), &resolver);
	assert_eq!(
		code,
		ExitCode::FAILURE,
		"the switch, not the file, sets the date"
	);
}

#[test]
fn a_domain_with_no_recorded_switch_is_refused_not_assumed_old() {
	let (install, zone) = split_install();
	std::fs::remove_file(install.data().join("dkim-split.json")).expect("remove");
	let (provider, resolver) = services(&zone);
	let (code, _, err, _) = run(&install, &FINISH, Some(provider), &resolver);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(
		err.contains("s1._domainkey.b.example.org: no split recorded for b.example.org"),
		"{err}"
	);
	assert!(zone.deleted.lock().unwrap().is_empty());
}

#[test]
fn skipping_the_overlap_check_is_explicit_and_warned() {
	let (install, zone) = split_install();
	// Restarted yesterday: inside the window.
	switched_days_ago(&install, 1);
	let (provider, resolver) = services(&zone);
	let options = Options {
		skip_overlap_check: true,
		..FINISH
	};
	let (code, _, err, _) = run(&install, &options, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS, "{err}");
	assert!(
		err.contains("--skip-overlap-check: retiring without the overlap window"),
		"{err}"
	);
	assert_eq!(zone.deleted.lock().unwrap().len(), 2);
}

#[test]
fn finish_retires_the_shared_key_with_its_exact_value_and_only_there() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	let (provider, resolver) = services(&zone);
	let (code, out, err, _) = run(&install, &FINISH, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS, "{out}\n{err}");
	let left = zone.published();
	assert!(
		left.contains(&"s1._domainkey.a.example.org".to_string()),
		"the domain that keeps the key keeps its record: {left:?}"
	);
	for gone in ["s1._domainkey.b.example.org", "s1._domainkey.c.example.org"] {
		assert!(!left.contains(&gone.to_string()), "{gone} still published");
		assert!(out.contains(&format!("retired TXT {gone}")), "{out}");
	}
	let deleted = zone.deleted.lock().unwrap().clone();
	assert_eq!(deleted.len(), 2, "{deleted:?}");
	assert!(
		deleted
			.iter()
			.all(|(_, value)| *value == shared_value(&install)),
		"deleted with the value that was read, never an empty one: {deleted:?}"
	);
	assert_eq!(
		left.iter().filter(|name| name.starts_with("own")).count(),
		2
	);
}

#[test]
fn another_key_at_the_same_name_is_reported_and_left_alone() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	let (_, foreign) = crate::dkim::generate_key().expect("key");
	zone.records
		.lock()
		.unwrap()
		.insert("s1._domainkey.b.example.org".into(), vec![foreign]);
	let (provider, resolver) = services(&zone);
	let (code, out, _, _) = run(&install, &FINISH, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(
		out.contains("not ours, left alone: s1._domainkey.b.example.org"),
		"{out}"
	);
	let deleted = zone.deleted.lock().unwrap().clone();
	assert_eq!(deleted.len(), 1, "only c's record: {deleted:?}");
	assert_eq!(deleted[0].0, "s1._domainkey.c.example.org");
	assert!(
		zone.published()
			.contains(&"s1._domainkey.b.example.org".to_string())
	);
}

#[test]
fn a_record_with_only_a_dkim_prefix_is_not_ours() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	for domain in ["b", "c"] {
		zone.records.lock().unwrap().insert(
			format!("s1._domainkey.{domain}.example.org"),
			vec!["v=DKIM1; k=ed25519; p=AAAA".into()],
		);
	}
	let (provider, resolver) = services(&zone);
	let (code, ..) = run(&install, &FINISH, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(zone.deleted.lock().unwrap().is_empty());
}

#[test]
fn a_lookup_that_fails_is_a_failure_and_removes_nothing() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	let (provider, _) = services(&zone);
	let (code, _, err, _) = run(&install, &FINISH, Some(provider), &Failing);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(
		err.contains("cannot tell whether the shared key is still published"),
		"{err}"
	);
	assert!(zone.deleted.lock().unwrap().is_empty());
}

#[test]
fn the_old_key_stays_while_the_domains_own_record_does_not_resolve() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	zone.records
		.lock()
		.unwrap()
		.retain(|name, _| !name.starts_with("own"));
	let (provider, resolver) = services(&zone);
	let (code, _, err, _) = run(&install, &FINISH, Some(provider), &resolver);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(err.contains("does not show the domain's own key"), "{err}");
	assert!(zone.deleted.lock().unwrap().is_empty());
}

#[test]
fn a_dry_run_of_finish_removes_nothing() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	let before = zone.published();
	let (provider, resolver) = services(&zone);
	let options = Options {
		dry_run: true,
		..FINISH
	};
	let (code, out, _, _) = run(&install, &options, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(
		out.contains("would retire s1._domainkey.b.example.org"),
		"{out}"
	);
	assert_eq!(zone.published(), before);
}

#[test]
fn without_a_provider_finish_lists_the_records_to_remove_by_hand() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	let before = zone.published();
	let (_, resolver) = services(&zone);
	let (code, out, _, _) = run(&install, &FINISH, None, &resolver);
	assert_eq!(
		code,
		ExitCode::from(4),
		"manual removal leaves the split unfinished"
	);
	assert!(
		out.contains("remove by hand: s1._domainkey.b.example.org"),
		"{out}"
	);
	assert!(!out.contains("s1._domainkey.a.example.org"), "{out}");
	assert_eq!(zone.published(), before);
}

#[test]
fn nothing_published_means_nothing_to_retire() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	zone.records
		.lock()
		.unwrap()
		.remove("s1._domainkey.b.example.org");
	zone.records
		.lock()
		.unwrap()
		.remove("s1._domainkey.c.example.org");
	let (provider, resolver) = services(&zone);
	let (code, out, _, _) = run(&install, &FINISH, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(out.contains("nothing to retire"), "{out}");
}
