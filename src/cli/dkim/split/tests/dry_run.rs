//! What `dkim split --dry-run` prints: every key a domain would get, the
//! file it is written to and the record it is published as, as the real run
//! makes them. A domain that signs with two keys gets two of each.

use std::path::PathBuf;
use std::process::ExitCode;

use super::finish::services;
use super::harness::{Install, Zone, run};
use crate::cli::dkim::split::Options;

const DRY: Options = Options {
	dry_run: true,
	wait: 0,
	finish: false,
	skip_overlap_check: false,
	restarted: false,
};

const SPLIT: Options = Options {
	dry_run: false,
	..DRY
};

/// The keys the dry run names: the domain, the selector and the file each
/// is written to.
fn keys_named(out: &str) -> Vec<(String, String, PathBuf)> {
	out.lines()
		.filter_map(|line| {
			let rest = line.strip_prefix("give ")?;
			let (domain, rest) = rest.split_once(" a key of its own (")?;
			let (selector, file) = rest.split_once(") at ")?;
			Some((
				domain.to_string(),
				selector.to_string(),
				PathBuf::from(file.trim()),
			))
		})
		.collect()
}

/// The records the dry run names.
fn records_named(out: &str) -> Vec<String> {
	out.lines()
		.filter_map(|line| line.strip_prefix("publish TXT "))
		.map(|rest| rest.split(',').next().unwrap_or(rest).trim().to_string())
		.collect()
}

#[test]
fn a_dry_run_names_both_keys_of_a_domain_that_gets_two() {
	let install = Install::with_rsa(&["a.example.org", "b.example.org"]);
	let zone = Zone::default();
	let (provider, resolver) = services(&zone);
	let (code, out, err, _) = run(&install, &DRY, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS, "{out}\n{err}");
	let keys = keys_named(&out);
	assert_eq!(keys.len(), 2, "one key for each signature: {out}");
	let (domain, ed, ed_file) = &keys[0];
	assert_eq!(domain, "b.example.org");
	assert!(ed.starts_with("own") && !ed.starts_with("ownrsa"), "{ed}");
	assert!(ed_file.ends_with("ed25519.pem"), "{}", ed_file.display());
	let (domain, rsa, rsa_file) = &keys[1];
	assert_eq!(domain, "b.example.org");
	assert!(rsa.starts_with("ownrsa"), "{rsa}");
	assert!(rsa_file.ends_with("rsa.pem"), "{}", rsa_file.display());
	assert_eq!(
		records_named(&out),
		[
			format!("{ed}._domainkey.b.example.org"),
			format!("{rsa}._domainkey.b.example.org"),
		]
	);
}

#[test]
fn a_dry_run_names_only_the_ed25519_key_when_only_it_signs() {
	let install = Install::new(&["a.example.org", "b.example.org"], "");
	let zone = Zone::default();
	let (provider, resolver) = services(&zone);
	let (code, out, err, _) = run(&install, &DRY, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS, "{out}\n{err}");
	let keys = keys_named(&out);
	assert_eq!(keys.len(), 1, "{out}");
	assert!(keys[0].1.starts_with("own"), "{out}");
	assert!(keys[0].2.ends_with("ed25519.pem"), "{out}");
	assert_eq!(records_named(&out).len(), 1, "{out}");
	assert!(!out.contains("ownrsa"), "{out}");
}

#[test]
fn the_dry_run_names_the_keys_the_real_run_creates() {
	let install = Install::with_rsa(&["a.example.org", "b.example.org"]);
	let zone = Zone::default();
	let (provider, resolver) = services(&zone);
	let (code, out, err, _) = run(&install, &DRY, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS, "{out}\n{err}");
	let named = keys_named(&out);
	let mut records = records_named(&out);

	// The real run, on the same fixture.
	let (provider, resolver) = services(&zone);
	let (code, out, err, _) = run(&install, &SPLIT, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS, "{out}\n{err}");

	let config = install.load();
	let dkim = config.dkim.expect("dkim");
	let entry = dkim.override_for("b.example.org").expect("the entry");
	let made = vec![
		(
			"b.example.org".to_string(),
			entry.selector.clone(),
			entry.key_file.clone(),
		),
		(
			"b.example.org".to_string(),
			entry.rsa_selector.clone().expect("the rsa selector"),
			entry.rsa_key_file.clone().expect("the rsa key file"),
		),
	];
	assert_eq!(named, made, "the dry run names the keys the run makes");
	let mut published = zone.published();
	published.sort();
	records.sort();
	assert_eq!(
		records, published,
		"the dry run names the records the run publishes"
	);
}
