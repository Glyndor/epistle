//! `dkim split --json` prints one object and nothing else on stdout.

use std::process::ExitCode;

use super::harness::{Install, Provider, Resolver, Zone, run_as};
use crate::cli::dkim::split::Options;

fn world(blind: bool) -> (Provider, Resolver) {
	let zone = Zone::default();
	(
		Provider {
			zone: zone.clone(),
			refuses: false,
		},
		Resolver { zone, blind },
	)
}

fn install() -> Install {
	Install::new(&["a.example.org", "b.example.org", "c.example.org"], "")
}

fn object(out: &str) -> serde_json::Value {
	serde_json::from_str(out.trim())
		.unwrap_or_else(|error| panic!("one JSON object: {error}: {out}"))
}

#[test]
fn a_dry_run_names_who_keeps_and_who_moves() {
	let (provider, resolver) = world(false);
	let options = Options {
		dry_run: true,
		wait: 0,
		finish: false,
		skip_overlap_check: false,
		restarted: false,
	};
	let (code, out, _, _) = run_as(&install(), &options, Some(provider), &resolver, true);
	assert_eq!(code, ExitCode::SUCCESS);
	let result = object(&out);
	assert_eq!(result["result"], "dry-run");
	assert_eq!(result["action"], "split");
	assert_eq!(result["keeps"], "a.example.org");
	let moved: Vec<_> = result["moves"]
		.as_array()
		.expect("moves")
		.iter()
		.map(|m| m["domain"].as_str().expect("domain"))
		.collect();
	assert_eq!(moved, ["b.example.org", "c.example.org"]);
}

#[test]
fn waiting_lists_the_records_that_do_not_resolve() {
	let (provider, resolver) = world(true);
	let options = Options {
		dry_run: false,
		wait: 0,
		finish: false,
		skip_overlap_check: false,
		restarted: false,
	};
	let (code, out, _, _) = run_as(&install(), &options, Some(provider), &resolver, true);
	assert_eq!(code, ExitCode::FAILURE);
	let result = object(&out);
	assert_eq!(result["result"], "waiting");
	assert_eq!(result["missing"].as_array().expect("missing").len(), 2);
}

#[test]
fn a_finished_split_says_the_server_was_restarted() {
	let install = install();
	let (provider, resolver) = world(false);
	let options = Options {
		dry_run: false,
		wait: 0,
		finish: false,
		skip_overlap_check: false,
		restarted: false,
	};
	let (code, out, _, _) = run_as(&install, &options, Some(provider), &resolver, true);
	assert_eq!(code, ExitCode::SUCCESS);
	let result = object(&out);
	assert_eq!(result["result"], "split");
	assert_eq!(result["reload"], "restarted");
}
