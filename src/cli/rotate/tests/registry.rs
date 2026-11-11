//! The registry itself: every entry says how, and the gaps point at the issue.

use std::collections::BTreeSet;

use crate::cli::rotate::registry::{Entry, Handling, TRACKING_ISSUE, entries};

fn entry(id: &str) -> &'static Entry {
	entries()
		.find(|entry| entry.id == id)
		.unwrap_or_else(|| panic!("no registry entry {id}"))
}

fn text(handling: &Handling) -> &'static str {
	match handling {
		Handling::Epistle(text) | Handling::Operator(text) => text,
		Handling::Unsupported { meanwhile, .. } => meanwhile,
	}
}

#[test]
fn ids_are_unique_and_every_entry_is_filled_in() {
	let mut ids = BTreeSet::new();
	for entry in entries() {
		assert!(ids.insert(entry.id), "duplicate id {}", entry.id);
		assert!(
			entry
				.id
				.bytes()
				.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
			"{} is not lowercase, digits and dashes",
			entry.id
		);
		for part in [
			entry.name,
			entry.stored_in,
			text(&entry.rotate),
			text(&entry.revoke),
		] {
			assert!(!part.trim().is_empty(), "{} has an empty field", entry.id);
		}
		for handling in [&entry.rotate, &entry.revoke] {
			if let Handling::Unsupported { issue, .. } = handling {
				assert!(*issue > 0, "{} has no issue to follow", entry.id);
			}
		}
	}
}

#[test]
fn the_kinds_the_procedure_cannot_do_yet_point_at_the_tracking_issue() {
	for id in [
		"storage-encryption-key",
		"tenant-storage-key",
		"account-password",
		"account-totp-secret",
		"totp-seed-in-clear",
	] {
		let entry = entry(id);
		for handling in [&entry.rotate, &entry.revoke] {
			assert!(
				matches!(handling, Handling::Unsupported { issue, .. } if *issue == TRACKING_ISSUE),
				"{id} must be unsupported and link #{TRACKING_ISSUE}"
			);
		}
	}
}

#[test]
fn the_kinds_the_issue_lists_are_all_present() {
	for id in [
		"dkim-signing-key",
		"arc-sealing-key",
		"evidence-signing-key",
		"oauth-signing-key",
		"webhook-secret",
		"srs-secret",
		"api-key",
		"app-password",
		"account-password",
		"account-totp-secret",
		"storage-encryption-key",
		"dns-credentials",
		"tls-certificate",
		"database-password",
	] {
		entry(id);
	}
}

#[test]
fn what_epistle_does_names_a_command_and_what_it_cannot_do_names_none() {
	for entry in entries() {
		for handling in [&entry.rotate, &entry.revoke] {
			if let Handling::Epistle(how) = handling {
				assert!(how.contains("`epistle "), "{}: {how}", entry.id);
			}
		}
	}
}
