//! The split end to end: records first, signing after, nothing in between.

use std::process::ExitCode;

use super::harness::{Install, Provider, Resolver, Zone, public, run, with_stack};
use crate::cli::dkim::split::Options;

const NOW: Options = Options {
	dry_run: false,
	wait: 0,
	finish: false,
	skip_overlap_check: false,
	restarted: false,
};

fn world(blind: bool, refuses: bool) -> (Zone, Provider, Resolver) {
	let zone = Zone::default();
	(
		zone.clone(),
		Provider {
			zone: zone.clone(),
			refuses,
		},
		Resolver { zone, blind },
	)
}

fn three() -> Install {
	Install::new(&["a.example.org", "b.example.org", "c.example.org"], "")
}

#[test]
fn a_split_publishes_first_and_switches_after() {
	let install = three();
	with_stack(&install);
	let (zone, provider, resolver) = world(false, false);
	let (code, out, err, restarts) = run(&install, &NOW, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS, "{out}\n{err}");
	let published = zone.published();
	assert_eq!(published.len(), 2, "{published:?}");
	assert!(
		published
			.iter()
			.all(|name| name.starts_with("own") && !name.starts_with("s1.")),
		"the new records use selectors the shared key does not: {published:?}"
	);
	let config = install.load();
	let dkim = config.dkim.expect("dkim");
	let names: Vec<_> = dkim.domain.iter().map(|d| d.name.as_str()).collect();
	assert_eq!(names, ["b.example.org", "c.example.org"]);
	assert!(
		dkim.override_for("a.example.org").is_none(),
		"a keeps [dkim]"
	);
	assert_eq!(restarts, 1, "the server restarts once, after the entries");
	// Each domain publishes the key it will sign with.
	for entry in &dkim.domain {
		let name = format!("{}._domainkey.{}", entry.selector, entry.name);
		let value = zone.records.lock().unwrap()[&name][0].clone();
		assert!(
			value == public(&entry.key_file),
			"a moved domain does not publish the key that signs"
		);
	}
	assert!(out.contains("a.example.org keeps the [dkim] key"), "{out}");
}

#[test]
fn nothing_switches_while_a_record_does_not_resolve() {
	let install = three();
	with_stack(&install);
	let before = install.text();
	let (zone, provider, resolver) = world(true, false);
	let (code, out, _, restarts) = run(&install, &NOW, Some(provider), &resolver);
	assert_eq!(code, ExitCode::FAILURE, "{out}");
	assert_eq!(install.text(), before, "the configuration is untouched");
	assert_eq!(restarts, 0, "and the server is not restarted");
	assert!(out.contains("not visible yet: own"), "{out}");
	assert_eq!(zone.published().len(), 2, "the records were published");
	assert!(
		install
			.data()
			.join("keys/dkim/b.example.org/ed25519.pem")
			.is_file(),
		"the keys are kept for the next run"
	);
}

#[test]
fn running_it_again_when_the_records_resolve_reuses_the_keys() {
	let install = three();
	let (_, provider, blind) = world(true, false);
	let (code, ..) = run(&install, &NOW, Some(provider), &blind);
	assert_eq!(code, ExitCode::FAILURE);
	let key = install.data().join("keys/dkim/b.example.org/ed25519.pem");
	let first = public(&key);
	let (_, provider, resolver) = world(false, false);
	let (code, out, err, _) = run(&install, &NOW, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS, "{out}\n{err}");
	assert_eq!(
		public(&key),
		first,
		"the key published first is the one that signs"
	);
	let config = install.load();
	let entry = config
		.dkim
		.expect("dkim")
		.override_for("b.example.org")
		.cloned()
		.expect("entry");
	assert_eq!(public(&entry.key_file), first);
}

#[test]
fn a_provider_that_refuses_stops_before_any_switch() {
	let install = three();
	let before = install.text();
	let (_, provider, resolver) = world(false, true);
	let (code, _, err, restarts) = run(&install, &NOW, Some(provider), &resolver);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(err.contains("cannot publish own"), "{err}");
	assert_eq!(install.text(), before);
	assert_eq!(restarts, 0);
}

#[test]
fn without_a_provider_the_records_are_printed_and_the_switch_waits_for_dns() {
	let install = three();
	let before = install.text();
	let (_, _, blind) = world(true, false);
	let (code, out, _, _) = run(&install, &NOW, None, &blind);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(out.contains("publish by hand: own"), "{out}");
	assert!(out.contains("IN TXT"), "{out}");
	assert_eq!(install.text(), before);
	// The operator publishes; the same command now switches.
	let (zone, _, resolver) = world(false, false);
	let config = install.load();
	for domain in ["b.example.org", "c.example.org"] {
		let dir = install.data().join("keys/dkim").join(domain);
		let selector = format!("own{}", day(&dir.join("ed25519.pem")));
		let value = public(&dir.join("ed25519.pem"));
		zone.records
			.lock()
			.unwrap()
			.insert(format!("{selector}._domainkey.{domain}"), vec![value]);
	}
	let _ = config;
	let (code, out, err, _) = run(&install, &NOW, None, &resolver);
	assert_eq!(code, ExitCode::SUCCESS, "{out}\n{err}");
	assert_eq!(install.load().dkim.expect("dkim").domain.len(), 2);
}

fn day(file: &std::path::Path) -> u64 {
	std::fs::metadata(file)
		.unwrap()
		.modified()
		.unwrap()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs()
		/ 86_400
}

#[test]
fn a_record_outside_the_zone_is_left_to_the_operator() {
	let install = Install::new(&["a.example.org", "b.example.org", "c.other.net"], "");
	let (zone, provider, resolver) = world(true, false);
	let (_, out, _, _) = run(&install, &NOW, Some(provider), &resolver);
	assert!(
		zone.published()
			.iter()
			.all(|name| name.ends_with(".example.org")),
		"{:?}",
		zone.published()
	);
	assert!(
		out.contains("publish by hand: own") && out.contains("._domainkey.c.other.net"),
		"{out}"
	);
}

#[test]
fn a_dry_run_changes_nothing() {
	let install = three();
	let before = install.text();
	let (zone, provider, resolver) = world(false, false);
	let options = Options {
		dry_run: true,
		wait: 0,
		finish: false,
		skip_overlap_check: false,
		restarted: false,
	};
	let (code, out, _, restarts) = run(&install, &options, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS);
	assert_eq!(install.text(), before);
	assert!(zone.published().is_empty(), "nothing is published");
	assert!(!install.data().join("keys").exists(), "no key is made");
	assert_eq!(restarts, 0);
	assert!(
		out.contains("keep a.example.org on the [dkim] key"),
		"{out}"
	);
	assert!(out.contains("dry run: nothing changed"), "{out}");
}

#[test]
fn an_install_with_a_key_per_domain_has_nothing_to_split() {
	let install = Install::new(&["a.example.org"], "");
	let (_, provider, resolver) = world(false, false);
	let (code, out, _, restarts) = run(&install, &NOW, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(out.contains("nothing to split"), "{out}");
	assert_eq!(restarts, 0);
}

#[test]
fn the_split_install_passes_the_sharing_checks() {
	let install = three();
	let (_, provider, resolver) = world(false, false);
	let (code, ..) = run(&install, &NOW, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS);
	let config = install.load();
	let dkim = config.dkim.as_ref().expect("dkim");
	assert!(
		dkim.shared_default_warning(&config.domains, &config.domain_aliases)
			.is_none()
	);
	assert_eq!(
		crate::dkim::sharing::shared_public_keys(&config),
		Ok(Vec::new())
	);
}
