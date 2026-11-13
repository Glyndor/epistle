//! The registry and the run agree on what the run does.

use crate::cli::rotate::registry::{Handling, entries};

use super::super::journal::Kind;
use super::super::report::HANDLED;

#[test]
fn every_row_the_run_carries_out_names_it_in_the_registry() {
	for (kind, id) in HANDLED {
		let entry = entries()
			.find(|entry| entry.id == *id)
			.unwrap_or_else(|| panic!("{kind:?} names {id}, which the registry does not have"));
		assert!(
			matches!(entry.rotate, Handling::Epistle(how) if how.contains("`epistle rotate --all`")),
			"{id} does not say that `epistle rotate --all` rotates it"
		);
	}
}

#[test]
fn every_kind_of_step_but_the_restart_maps_to_a_registry_row() {
	for kind in [
		Kind::ApiKey,
		Kind::AppPassword,
		Kind::WebhookSecret,
		Kind::SrsSecret,
		Kind::DkimKey,
		Kind::DkimDomainKey,
	] {
		assert!(
			HANDLED.iter().any(|(handled, _)| *handled == kind),
			"{kind:?} has no registry row"
		);
	}
	assert!(!HANDLED.iter().any(|(kind, _)| *kind == Kind::Restart));
}

#[test]
fn a_row_the_registry_says_the_run_does_is_one_it_does() {
	for entry in entries() {
		if let Handling::Epistle(how) = entry.rotate
			&& how.contains("`epistle rotate --all`")
		{
			assert!(
				HANDLED.iter().any(|(_, id)| *id == entry.id),
				"{} says `epistle rotate --all` rotates it, and the run has no step for it",
				entry.id
			);
		}
	}
}
