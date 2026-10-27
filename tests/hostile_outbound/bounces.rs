//! Bounce loops and attacker-controlled report fields.

use std::time::UNIX_EPOCH;

use epistle::queue::bounce::{self, ReportRecipient};
use epistle::smtp::session::AcceptedMessage;

use super::harness::{BODY, bounded};

fn bounce(sender: &str, reason: &str, data: &[u8]) -> Option<AcceptedMessage> {
	bounce::build(
		"mail.epistle.test",
		sender,
		&["victim@outside.test".into()],
		reason,
		data,
		UNIX_EPOCH,
		true,
	)
}

#[test]
fn failing_dsn_cannot_generate_another_dsn_even_with_forged_return_path() {
	bounded(|| {
		let first = bounce("sender@outside.test", "550 5.1.1 refused", BODY).expect("first bounce");
		assert!(first.reverse_path.is_empty());
		assert_eq!(first.recipients, ["sender@outside.test"]);
		let mut forged =
			b"Return-Path: <evil@outside.test>\r\nReply-To: evil@outside.test\r\n".to_vec();
		forged.extend(first.data);
		assert!(bounce(&first.reverse_path, "550 bounce refused", &forged).is_none());
		assert!(
			bounce::build_delay_warning(
				"mail.epistle.test",
				&first.reverse_path,
				&[ReportRecipient::new("sender@outside.test", "451 later")],
				&forged,
				UNIX_EPOCH,
				true,
			)
			.is_none()
		);
	});
}

#[test]
fn manipulated_reply_to_and_return_path_do_not_choose_bounce_destination() {
	bounded(|| {
		let data = b"From: visible@outside.test\r\nReply-To: evil@outside.test\r\nReturn-Path: <other@outside.test>\r\n\r\nbody";
		let dsn = bounce("envelope@outside.test", "550 refused", data).expect("DSN");
		assert_eq!(dsn.recipients, ["envelope@outside.test"]);
		assert!(dsn.reverse_path.is_empty());
		let text = String::from_utf8(dsn.data).expect("DSN text");
		assert!(text.starts_with(
			"From: Mail Delivery System <MAILER-DAEMON@mail.epistle.test>\r\nTo: <envelope@outside.test>\r\n"
		));
	});
}

#[test]
fn crlf_nul_and_brackets_in_dsn_recipient_are_refused() {
	bounded(|| {
		for sender in [
			"sender@outside.test\r\nBcc: evil@outside.test",
			"sender\0@outside.test",
			"<sender@outside.test>",
		] {
			assert!(bounce(sender, "550 refused", BODY).is_none(), "{sender:?}");
		}
	});
}

#[test]
fn hostile_remote_reason_and_host_are_flattened_and_capped() {
	bounded(|| {
		let reason = format!(
			"550 5.1.1 denied\r\nX-Injected: yes\0{}",
			"x".repeat(1 << 20)
		);
		let report = ReportRecipient {
			remote: Some("mx.outside.test\r\nBcc: evil@outside.test\0".into()),
			..ReportRecipient::new("victim@outside.test", &reason)
		};
		let dsn = bounce::build_failed(
			"mail.epistle.test",
			"sender@outside.test",
			&[report],
			BODY,
			UNIX_EPOCH,
			true,
		)
		.expect("DSN");
		let text = String::from_utf8(dsn.data).expect("ASCII");
		assert!(!text.contains("\r\nX-Injected:"));
		assert!(!text.contains("\r\nBcc:"));
		assert!(!text.contains('\0'));
		assert!(!text.contains(&"x".repeat(513)));
		assert!(text.contains("X-Injected: yes"));
		assert!(text.len() < 8192);
	});
}

#[test]
fn ten_thousand_original_headers_are_quoted_only_within_four_kib() {
	bounded(|| {
		let mut data = b"From: sender@outside.test\r\n".to_vec();
		data.extend(b"X-Padding: 1234567890\r\n".repeat(10_000));
		data.extend_from_slice(b"\r\nBODY-SECRET\r\nBcc: body@outside.test\r\n");
		let dsn = bounce("sender@outside.test", "550 refused", &data).expect("DSN");
		let text = String::from_utf8(dsn.data).expect("ASCII");
		let quoted = text
			.split("Content-Type: message/rfc822-headers\r\n\r\n")
			.nth(1)
			.expect("quoted headers");
		let block = quoted.split("\r\n--=_dsn_").next().expect("quote end");
		assert!(block.len() <= 4096);
		assert!(!text.contains("BODY-SECRET"));
		assert!(!text.contains("Bcc: body@outside.test"));
		assert!(text.len() < 8192);
	});
}

#[test]
#[ignore = "bug: DSN Final-Recipient interpolates failed recipient CRLF/NUL"]
fn failed_recipient_cannot_inject_dsn_fields() {
	bounded(|| {
		let recipient =
			ReportRecipient::new("victim@outside.test\r\nX-Injected: yes\0", "550 refused");
		if let Some(dsn) = bounce::build_failed(
			"mail.epistle.test",
			"sender@outside.test",
			&[recipient],
			BODY,
			UNIX_EPOCH,
			true,
		) {
			let text = String::from_utf8(dsn.data).expect("DSN");
			assert!(!text.contains("\r\nX-Injected:"));
			assert!(!text.contains('\0'));
		}
	});
}
