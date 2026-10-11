//! Confirmations printed after an operator command state what changed. They
//! do not repeat the account name the operator just typed.

use super::*;
use crate::config::Protocol;

#[test]
fn quota_confirmation_states_the_new_value_only() {
	assert_eq!(
		account::quota_changed(Some(20 * 1024 * 1024 * 1024)),
		"quota set to 21474836480"
	);
	assert_eq!(account::quota_changed(None), "quota set to server default");
}

#[test]
fn protocols_confirmation_states_the_new_value_only() {
	let imap_api = vec![Protocol::Imap, Protocol::Api];
	assert_eq!(
		account::protocols_changed(Some(&imap_api)),
		"protocols set to imap,api"
	);
	assert_eq!(account::protocols_changed(None), "protocols set to all");
}

#[test]
fn export_summary_counts_messages_without_naming_the_account() {
	assert_eq!(export::exported_summary(3), "exported 3 messages");
	assert_eq!(export::exported_summary(0), "exported 0 messages");
}
