//! After a split the shared key is still published at the domains that left
//! it. The report names those records; `--finish` retires them once the
//! overlap has passed and never touches the domain that kept the key.

use std::process::ExitCode;

use super::harness::{Install, Provider, Resolver, Zone, run, run_as};
use crate::cli::dkim::split::Options;

const SPLIT: Options = Options {
	dry_run: false,
	wait: 0,
	finish: false,
};
const FINISH: Options = Options {
	dry_run: false,
	wait: 0,
	finish: true,
};
const SHARED: &str = "v=DKIM1; k=ed25519; p=AAAA";

/// A three-domain install that has been split, with the shared key's `s1`
/// record published at all three domains, as it is after a real split.
fn split_install() -> (Install, Zone) {
	let install = Install::new(&["a.example.org", "b.example.org", "c.example.org"], "");
	let zone = Zone::default();
	for domain in ["a", "b", "c"] {
		zone.records.lock().unwrap().insert(
			format!("s1._domainkey.{domain}.example.org"),
			vec![SHARED.to_string()],
		);
	}
	let provider = Provider {
		zone: zone.clone(),
		refuses: false,
	};
	let resolver = Resolver {
		zone: zone.clone(),
		blind: false,
	};
	let (code, ..) = run(&install, &SPLIT, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS);
	(install, zone)
}

fn services(zone: &Zone) -> (Provider, Resolver) {
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

/// Make the moved domains' own keys `days` days old.
fn age_keys(install: &Install, days: u64) {
	let when = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400);
	for domain in ["b.example.org", "c.example.org"] {
		let file = install
			.data()
			.join("keys/dkim")
			.join(domain)
			.join("ed25519.pem");
		std::fs::File::options()
			.write(true)
			.open(file)
			.expect("open")
			.set_modified(when)
			.expect("mtime");
	}
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
	assert!(
		!out.contains("s1._domainkey.a.example.org"),
		"the domain that keeps the key is not listed: {out}"
	);
}

#[test]
fn finish_waits_for_the_overlap_and_retires_nothing_before() {
	let (install, zone) = split_install();
	let before = zone.published();
	let (provider, resolver) = services(&zone);
	let (code, out, err, _) = run(&install, &FINISH, Some(provider), &resolver);
	assert_eq!(code, ExitCode::FAILURE, "{out}");
	assert!(err.contains("overlap window has not passed"), "{err}");
	assert!(out.contains("(not before "), "{out}");
	assert_eq!(zone.published(), before, "nothing was removed");
}

#[test]
fn finish_retires_the_shared_key_at_the_moved_domains_and_only_there() {
	let (install, zone) = split_install();
	age_keys(&install, 20);
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
	assert_eq!(
		left.iter().filter(|name| name.starts_with("own")).count(),
		2,
		"the new keys' own records stay: {left:?}"
	);
}

#[test]
fn a_dry_run_of_finish_removes_nothing() {
	let (install, zone) = split_install();
	age_keys(&install, 20);
	let before = zone.published();
	let (provider, resolver) = services(&zone);
	let options = Options {
		dry_run: true,
		wait: 0,
		finish: true,
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
	age_keys(&install, 20);
	let before = zone.published();
	let (_, resolver) = services(&zone);
	let (code, out, _, _) = run(&install, &FINISH, None, &resolver);
	assert_eq!(code, ExitCode::SUCCESS);
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
	age_keys(&install, 20);
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
