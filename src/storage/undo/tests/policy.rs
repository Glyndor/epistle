//! Which delay an account gets: the most specific scope wins, zero turns the
//! hold off, and nothing is ever above the ceiling.

use super::harness::{config, directory};
use crate::storage::undo::UndoPolicy;

fn delay(section: &str, account: &str) -> u32 {
	UndoPolicy::from_config(&config(section)).delay_for(&directory().current(), account)
}

#[test]
fn with_no_section_nothing_is_held() {
	assert!(UndoPolicy::from_config(&config("")).is_off());
	assert_eq!(delay("", "alice"), 0);
}

#[test]
fn the_server_delay_applies_to_everyone() {
	let section = "[queue.undo_send]\ndelay_secs = 30\n";
	assert!(!UndoPolicy::from_config(&config(section)).is_off());
	assert_eq!(delay(section, "alice"), 30);
	assert_eq!(delay(section, "bob"), 30);
}

#[test]
fn the_most_specific_scope_wins() {
	let section = "[queue.undo_send]\ndelay_secs = 10\n\
		[[queue.undo_send.scope]]\ntenant = \"acme\"\ndelay_secs = 20\n\
		[[queue.undo_send.scope]]\ndomain = \"example.org\"\ndelay_secs = 30\n\
		[[queue.undo_send.scope]]\naccount = \"alice\"\ndelay_secs = 40\n";
	assert_eq!(delay(section, "alice"), 40);
	// bob has no scope of his own: his domain's applies, over the tenant's.
	assert_eq!(delay(section, "bob"), 30);
	let tenant_only = "[queue.undo_send]\ndelay_secs = 10\n\
		[[queue.undo_send.scope]]\ntenant = \"acme\"\ndelay_secs = 20\n";
	assert_eq!(delay(tenant_only, "bob"), 20);
}

#[test]
fn a_scope_of_zero_turns_the_hold_off_for_it() {
	let section = "[queue.undo_send]\ndelay_secs = 60\n\
		[[queue.undo_send.scope]]\naccount = \"alice\"\ndelay_secs = 0\n";
	assert_eq!(delay(section, "alice"), 0);
	assert_eq!(delay(section, "bob"), 60);
}

#[test]
fn a_scope_alone_can_turn_the_hold_on_for_one_account() {
	let section = "[[queue.undo_send.scope]]\naccount = \"alice\"\ndelay_secs = 15\n";
	assert!(!UndoPolicy::from_config(&config(section)).is_off());
	assert_eq!(delay(section, "alice"), 15);
	assert_eq!(delay(section, "bob"), 0);
}

#[test]
fn no_delay_is_above_the_ceiling_even_if_the_file_says_so() {
	// The load refuses these; the policy holds the ceiling regardless.
	let section = "[queue.undo_send]\nmax_secs = 120\ndelay_secs = 500\n\
		[[queue.undo_send.scope]]\naccount = \"alice\"\ndelay_secs = 121\n";
	assert_eq!(delay(section, "alice"), 120);
	assert_eq!(delay(section, "bob"), 120);
	let at_ceiling = "[queue.undo_send]\nmax_secs = 120\ndelay_secs = 120\n";
	assert_eq!(delay(at_ceiling, "bob"), 120);
}

#[test]
fn a_ceiling_of_zero_makes_the_feature_unavailable() {
	let section = "[queue.undo_send]\nmax_secs = 0\ndelay_secs = 60\n";
	assert!(UndoPolicy::from_config(&config(section)).is_off());
	assert_eq!(delay(section, "alice"), 0);
}
