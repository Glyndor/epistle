//! Confirmations printed after an operator command state what changed. They
//! do not repeat the account name the operator just typed.

use super::*;
use crate::config::Protocol;

#[test]
fn quota_confirmation_names_the_change_only() {
	assert_eq!(
		account::quota_changed(Some(10 * 1024 * 1024 * 1024), Some(20 * 1024 * 1024 * 1024)),
		"quota changed: 10737418240 -> 21474836480"
	);
	assert_eq!(
		account::quota_changed(None, Some(1024)),
		"quota changed: server default -> 1024"
	);
	assert_eq!(
		account::quota_changed(Some(1024), None),
		"quota changed: 1024 -> server default"
	);
}

#[test]
fn protocols_confirmation_names_the_change_only() {
	let imap_api = vec![Protocol::Imap, Protocol::Api];
	assert_eq!(
		account::protocols_changed(None, Some(&imap_api)),
		"protocols changed: all -> imap,api"
	);
	assert_eq!(
		account::protocols_changed(Some(&imap_api), None),
		"protocols changed: imap,api -> all"
	);
}

#[test]
fn export_summary_counts_messages_without_naming_the_account() {
	assert_eq!(export::exported_summary(3), "exported 3 messages");
	assert_eq!(export::exported_summary(0), "exported 0 messages");
}
