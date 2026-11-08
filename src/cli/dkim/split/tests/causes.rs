//! Why a record the resolver does not show is not there: the command asks
//! the zone's own nameservers and says what they serve.

use std::process::ExitCode;
use std::sync::Arc;

use super::harness::{Failing, Install, Provider, Resolver, Zone, run_with_authority, with_stack};
use super::zone_authority::ZoneAuthority;
use crate::cli::dkim::split::Options;
use crate::dns::provider::DnsProvider;

const NOW: Options = Options {
	dry_run: false,
	wait: 0,
	finish: false,
	skip_overlap_check: false,
	restarted: false,
};

/// A run whose resolver shows nothing, against the nameservers `authority`
/// builds from the zone the run publishes into.
fn blind_run(json: bool, authority: impl FnOnce(Zone) -> ZoneAuthority) -> (ExitCode, String) {
	let install = Install::new(&["a.example.org", "b.example.org", "c.example.org"], "");
	with_stack(&install);
	let zone = Zone::default();
	let provider: Arc<dyn DnsProvider> = Arc::new(Provider {
		zone: zone.clone(),
		refuses: false,
	});
	let resolver = Resolver {
		zone: zone.clone(),
		blind: true,
	};
	let authority = authority(zone);
	let (code, out, ..) = run_with_authority(
		&install,
		&NOW,
		Some(provider),
		&resolver,
		Some(&authority),
		json,
	);
	(code, out)
}

#[test]
fn a_zone_that_serves_it_while_the_resolver_holds_a_negative_answer_is_named() {
	let (code, out) = blind_run(false, ZoneAuthority::new);
	assert_eq!(code, ExitCode::FAILURE, "{out}");
	assert!(
		out.contains("holds a cached negative answer (good for up to 1800 s)"),
		"{out}"
	);
}

#[test]
fn servers_that_do_not_agree_are_named_as_still_propagating() {
	let (_, out) = blind_run(false, |zone| ZoneAuthority {
		partial: true,
		..ZoneAuthority::new(zone)
	});
	assert!(out.contains("do not agree"), "{out}");
}

#[test]
fn a_zone_that_does_not_serve_it_says_it_has_not_arrived() {
	let (_, out) = blind_run(false, |zone| ZoneAuthority {
		blind: true,
		..ZoneAuthority::new(zone)
	});
	assert!(out.contains("the record has not reached the zone"), "{out}");
}

#[test]
fn a_server_that_does_not_answer_leaves_the_cause_unknown() {
	let (_, out) = blind_run(false, |zone| ZoneAuthority {
		blind: true,
		silent: 1,
		..ZoneAuthority::new(zone)
	});
	assert!(
		out.contains("could not be asked, so the reason is unknown"),
		"{out}"
	);
}

#[test]
fn the_json_carries_the_cause_and_the_remaining_ttl_of_each_record() {
	let (_, out) = blind_run(true, ZoneAuthority::new);
	assert!(out.contains("\"cause\":\"cached-negative\""), "{out}");
	assert!(out.contains("\"negative_ttl\":1800"), "{out}");
}

#[test]
fn a_resolver_that_failed_is_not_blamed_for_a_cached_negative_answer() {
	let install = Install::new(&["a.example.org", "b.example.org", "c.example.org"], "");
	with_stack(&install);
	let zone = Zone::default();
	let provider: Arc<dyn DnsProvider> = Arc::new(Provider {
		zone: zone.clone(),
		refuses: false,
	});
	let authority = ZoneAuthority::new(zone);
	let (_, out, ..) = run_with_authority(
		&install,
		&NOW,
		Some(provider),
		&Failing,
		Some(&authority),
		false,
	);
	assert!(
		out.contains("the host's resolver does not show it"),
		"{out}"
	);
	assert!(!out.contains("cached negative answer"), "{out}");
}
