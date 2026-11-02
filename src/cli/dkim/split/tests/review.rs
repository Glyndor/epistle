//! Cases an independent review found in the split: a selector that collides
//! with the shared key's, a restart that never happened, a rotation that
//! retired a selector the split had to remember, two runs at once, and a
//! record that cannot verify.

use std::process::ExitCode;

use super::finish::{FINISH, services, split_install, switched_days_ago};
use super::harness::{Install, Resolver, Zone, run, run_as, without_stack};
use crate::cli::dkim::split::Options;
use crate::dkim::split_state;

const SPLIT: Options = Options {
	dry_run: false,
	wait: 0,
	finish: false,
	skip_overlap_check: false,
	restarted: false,
};

fn today() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs()
		/ 86_400
}

fn shared_record(install: &Install, selector: &str) -> String {
	crate::dkim::Signer::load(selector, &install.dir.path().join("default.pem"))
		.expect("loads")
		.dns_record_value()
}

// ---- 1: the new selector is not the shared key's

#[test]
fn a_new_key_never_takes_the_selector_the_shared_key_is_published_under() {
	let shared = format!("own{}", today());
	let install = Install::with_selector(&["a.example.org", "b.example.org"], "", &shared);
	let zone = Zone::default();
	let name = format!("{shared}._domainkey.b.example.org");
	let value = shared_record(&install, &shared);
	zone.records
		.lock()
		.unwrap()
		.insert(name.clone(), vec![value.clone()]);
	let (provider, resolver) = services(&zone);
	let (code, out, err, _) = run(&install, &SPLIT, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS, "{out}\n{err}");
	assert_eq!(
		zone.records.lock().unwrap()[&name],
		[value],
		"the record the server still signs with was not replaced"
	);
	let dkim = install.load().dkim.unwrap();
	assert_eq!(
		dkim.override_for("b.example.org").unwrap().selector,
		format!("{shared}x2")
	);
}

// ---- 2: the restart

#[test]
fn a_split_without_a_confirmed_restart_is_pending_and_exits_4() {
	let install = Install::new(&["a.example.org", "b.example.org"], "");
	without_stack(&install);
	let zone = Zone::default();
	let (provider, resolver) = services(&zone);
	let (code, out, _, restarts) = run(&install, &SPLIT, Some(provider), &resolver);
	assert_eq!(code, ExitCode::from(4), "{out}");
	assert_eq!(restarts, 0);
	assert!(out.contains("NOT confirmed to run the moved keys"), "{out}");
	assert_eq!(
		split_state::pending(&install.data(), |_| true).unwrap(),
		["b.example.org"]
	);
}

#[test]
fn running_it_again_repeats_the_restart_instead_of_saying_nothing_to_split() {
	let install = Install::new(&["a.example.org", "b.example.org"], "");
	without_stack(&install);
	let zone = Zone::default();
	let (provider, resolver) = services(&zone);
	run(&install, &SPLIT, Some(provider), &resolver);
	super::harness::with_stack(&install);
	let (provider, resolver) = services(&zone);
	let (code, out, _, restarts) = run(&install, &SPLIT, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS, "{out}");
	assert_eq!(restarts, 1, "the pending restart was made");
	assert!(out.contains("restarted onto the moved keys"), "{out}");
	assert!(
		split_state::pending(&install.data(), |_| true)
			.unwrap()
			.is_empty()
	);
}

#[test]
fn finish_retires_nothing_while_the_server_is_not_confirmed_on_the_new_key() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	// Undo the restart: the entry is saved, the server was never restarted.
	let file = install.data().join("dkim-split.json");
	let mut state: serde_json::Value =
		serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
	for moved in state.as_object_mut().unwrap().values_mut() {
		moved.as_object_mut().unwrap().remove("restarted");
	}
	std::fs::write(&file, state.to_string()).unwrap();
	let (provider, resolver) = services(&zone);
	let options = Options {
		skip_overlap_check: true,
		..FINISH
	};
	let (code, _, err, _) = run(&install, &options, Some(provider), &resolver);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(
		err.contains("not confirmed to run the new key of b.example.org"),
		"{err}"
	);
	assert!(
		zone.deleted.lock().unwrap().is_empty(),
		"the skip flag does not lift this"
	);
}

#[test]
fn recording_a_restart_done_by_hand_lets_the_overlap_start() {
	let install = Install::new(&["a.example.org", "b.example.org"], "");
	without_stack(&install);
	let zone = Zone::default();
	let (provider, resolver) = services(&zone);
	run(&install, &SPLIT, Some(provider), &resolver);
	let options = Options {
		restarted: true,
		..SPLIT
	};
	let (code, out, _, _) = run(&install, &options, None, &Resolver { zone, blind: false });
	assert_eq!(code, ExitCode::SUCCESS, "{out}");
	assert!(
		split_state::pending(&install.data(), |_| true)
			.unwrap()
			.is_empty()
	);
}

// ---- 3: a rotation retired a selector the split recorded

#[test]
fn a_selector_a_rotation_has_since_retired_is_still_retired_by_finish() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	// The split recorded an older selector of the shared key; the rotation has
	// since removed it from the configuration's view and from the state.
	let value = shared_record(&install, "s1");
	let p = value.rsplit("p=").next().unwrap().to_string();
	let file = install.data().join("dkim-split.json");
	let mut state: serde_json::Value =
		serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
	state["b.example.org"]["stale"]
		.as_array_mut()
		.unwrap()
		.push(serde_json::json!({ "selector": "ed90", "expected": [p] }));
	std::fs::write(&file, state.to_string()).unwrap();
	zone.records
		.lock()
		.unwrap()
		.insert("ed90._domainkey.b.example.org".into(), vec![value]);
	let (provider, resolver) = services(&zone);
	let (code, out, err, _) = run(&install, &FINISH, Some(provider), &resolver);
	assert_eq!(code, ExitCode::SUCCESS, "{out}\n{err}");
	assert!(
		!zone
			.published()
			.contains(&"ed90._domainkey.b.example.org".to_string()),
		"{:?}",
		zone.published()
	);
}

// ---- 5: two runs at once

#[test]
fn a_second_run_on_the_same_data_directory_is_refused_while_the_first_holds_the_lock() {
	let install = Install::new(&["a.example.org", "b.example.org"], "");
	let _first = split_state::lock(&install.data(), std::time::Duration::from_millis(100)).unwrap();
	let before = install.text();
	let zone = Zone::default();
	let (provider, resolver) = services(&zone);
	let (code, _, err, _) = run(&install, &SPLIT, Some(provider), &resolver);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(err.contains("another dkim split is running"), "{err}");
	assert_eq!(install.text(), before);
	assert!(zone.published().is_empty(), "nothing was published");
}

// ---- 6: a record that cannot verify

#[test]
fn a_new_record_that_no_verifier_can_use_does_not_switch_signing() {
	for tamper in [
		(|v: &str| v.replace("k=ed25519", "k=rsa")) as fn(&str) -> String,
		|v: &str| format!("{v}; h=sha1"),
		|v: &str| format!("{v}; p=AAAA"),
	] {
		let install = Install::new(&["a.example.org", "b.example.org"], "");
		let before = install.text();
		let zone = Zone::default();
		*zone.tamper.lock().unwrap() = Some(tamper);
		let (provider, resolver) = services(&zone);
		let (code, out, _, restarts) = run(&install, &SPLIT, Some(provider), &resolver);
		assert_eq!(code, ExitCode::FAILURE, "{out}");
		assert!(out.contains("not visible yet"), "{out}");
		assert_eq!(install.text(), before);
		assert_eq!(restarts, 0);
	}
}

#[test]
fn the_domains_own_record_must_be_usable_before_the_old_one_goes() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	for (name, values) in zone.records.lock().unwrap().iter_mut() {
		if name.starts_with("own") {
			for value in values.iter_mut() {
				*value = value.replace("k=ed25519", "k=rsa");
			}
		}
	}
	let (provider, resolver) = services(&zone);
	let (code, _, err, _) = run(&install, &FINISH, Some(provider), &resolver);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(err.contains("does not show the domain's own key"), "{err}");
	assert!(zone.deleted.lock().unwrap().is_empty());
}

#[test]
fn the_json_of_a_pending_restart_says_so() {
	let install = Install::new(&["a.example.org", "b.example.org"], "");
	without_stack(&install);
	let zone = Zone::default();
	let (provider, resolver) = services(&zone);
	let (code, out, _, _) = run_as(&install, &SPLIT, Some(provider), &resolver, true);
	assert_eq!(code, ExitCode::from(4));
	let result: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
	assert_eq!(result["result"], "restart-pending");
	assert_eq!(result["reload"], "restart-needed");
}

// ---- a second move of a domain that was already restarted

#[test]
fn a_new_split_of_a_restarted_domain_does_not_inherit_the_old_confirmation() {
	let (install, zone) = split_install();
	switched_days_ago(&install, 20);
	// b.example.org loses its entry and is split again, and this time the
	// server cannot be restarted.
	let text = install.text();
	let kept: Vec<&str> = text
		.split("[[dkim.domain]]")
		.filter(|part| !part.contains("name = \"b.example.org\""))
		.collect();
	std::fs::write(&install.config, kept.join("[[dkim.domain]]")).unwrap();
	without_stack(&install);
	let (provider, resolver) = services(&zone);
	let (code, out, _, _) = run(&install, &SPLIT, Some(provider), &resolver);
	assert_eq!(code, ExitCode::from(4), "{out}");
	let state = split_state::read(&install.data()).unwrap();
	assert_eq!(
		state["b.example.org"].restarted, None,
		"the old confirmation is gone"
	);
	let (provider, resolver) = services(&zone);
	let (code, _, err, _) = run(&install, &FINISH, Some(provider), &resolver);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(
		err.contains("not confirmed to run the new key of b.example.org"),
		"{err}"
	);
}

#[test]
fn a_restart_confirmation_never_seals_a_move_whose_entry_is_not_in_the_file() {
	let install = Install::new(&["a.example.org", "b.example.org"], "");
	without_stack(&install);
	let zone = Zone::default();
	let (provider, resolver) = services(&zone);
	run(&install, &SPLIT, Some(provider), &resolver);
	split_state::record_written(&install.data(), "ghost.example.org", 5, vec![]).unwrap();
	let options = Options {
		restarted: true,
		..SPLIT
	};
	run(&install, &options, None, &Resolver { zone, blind: false });
	let state = split_state::read(&install.data()).unwrap();
	assert!(state["b.example.org"].restarted.is_some());
	assert_eq!(state["ghost.example.org"].restarted, None);
}
