//! The reminder only shows for the providers the server delivers to, and
//! `remind = false` turns it off.

use super::support::{EVERY_PROVIDER, report_after};
use crate::cli::status::report::{AreaReport, Level};

fn names(report: &AreaReport) -> Vec<&str> {
	report.items.iter().map(|item| item.name.as_str()).collect()
}

#[test]
fn nothing_delivered_means_nothing_to_remind() {
	let report = report_after("", &[]);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(report.items.is_empty());
}

#[test]
fn only_the_providers_delivered_to_are_reminded() {
	let report = report_after("", &["gmail-smtp-in.l.google.com"]);
	assert_eq!(report.status, Level::Warn, "{report:?}");
	assert_eq!(names(&report), ["postmaster"]);

	let report = report_after("", &[EVERY_PROVIDER[1]]);
	assert_eq!(names(&report), ["snds", "jmrp"]);

	let report = report_after("", &[EVERY_PROVIDER[2], EVERY_PROVIDER[3]]);
	assert_eq!(names(&report), ["yahoo-cfl", "apple"]);
}

#[test]
fn a_provider_the_panels_do_not_cover_is_not_reminded() {
	let report = report_after("", &["mx00.emig.gmx.net", "mail.example.net"]);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(report.items.is_empty());
}

#[test]
fn an_enrolled_panel_is_hidden_even_when_delivered_to() {
	let report = report_after(
		"[deliverability]\nenrolled = ['postmaster']\n",
		&["gmail-smtp-in.l.google.com"],
	);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(report.items.is_empty());
}

#[test]
fn the_setting_turns_the_reminder_off() {
	let report = report_after("[deliverability]\nremind = false\n", &EVERY_PROVIDER);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(report.items.is_empty());
	assert!(
		report.detail.contains("remind = false"),
		"{}",
		report.detail
	);
}

#[test]
fn the_reminder_is_on_unless_the_setting_says_otherwise() {
	let report = report_after("[deliverability]\nremind = true\n", &EVERY_PROVIDER);
	assert_eq!(report.status, Level::Warn, "{report:?}");
	assert_eq!(report.items.len(), 5);
}

#[test]
fn a_smarthost_answering_for_a_provider_is_not_delivery_to_it() {
	let transport = "[[transport]]\nkind = 'relay'\nhost = 'smtp.google.com'\nport = 587\n";
	let report = report_after(transport, &["smtp.google.com"]);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(report.items.is_empty());
}

#[test]
fn a_log_that_is_off_cannot_say_where_mail_went() {
	let report = report_after("[storage]\ndelivery_log_days = 0\n", &EVERY_PROVIDER);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(report.items.is_empty());
}
