use super::*;
use crate::antispam::attachments::PartReport;
use crate::antispam::attachments::sniff::RealType;

fn policy(mode: AttachmentMode, macros: ContentAction, encrypted: ContentAction) -> Policy {
	Policy::from_config(
		&Attachments {
			mode,
			macros,
			encrypted_archives: encrypted,
			..Attachments::default()
		},
		1 << 20,
	)
	.expect("mode is not off")
}

fn report(reasons: &[Reason]) -> Report {
	Report {
		parts: vec![PartReport {
			filename: Some("x".into()),
			declared_type: "application/octet-stream".into(),
			real_type: RealType::Unknown,
			reasons: reasons.to_vec(),
		}],
		..Report::default()
	}
}

fn action(policy: &Policy, reasons: &[Reason]) -> Action {
	policy.decide(&report(reasons)).action
}

#[test]
fn dangerous_content_follows_the_mode() {
	use ContentAction::Flag as F;
	for (mode, expected) in [
		(AttachmentMode::Flag, Action::Flag),
		(AttachmentMode::Quarantine, Action::Quarantine),
		(AttachmentMode::Reject, Action::Reject),
	] {
		let policy = policy(mode, F, F);
		assert_eq!(
			action(&policy, &[Reason::DangerousExtension]),
			expected,
			"{mode:?}"
		);
		assert_eq!(
			action(&policy, &[Reason::ExecutableContent]),
			expected,
			"{mode:?}"
		);
		assert_eq!(
			action(&policy, &[Reason::TypeMismatch]),
			expected,
			"{mode:?}"
		);
	}
}

#[test]
fn what_was_not_inspected_is_at_least_flagged_and_never_rejected_alone() {
	use ContentAction::Flag as F;
	for reason in [
		Reason::ScanLimit,
		Reason::AmbiguousMime,
		Reason::UnreadableArchive,
		Reason::NestedArchive,
	] {
		assert_eq!(
			action(&policy(AttachmentMode::Flag, F, F), &[reason]),
			Action::Flag,
			"{reason:?}"
		);
		assert_eq!(
			action(&policy(AttachmentMode::Quarantine, F, F), &[reason]),
			Action::Quarantine,
			"{reason:?}"
		);
		assert_eq!(
			action(&policy(AttachmentMode::Reject, F, F), &[reason]),
			Action::Quarantine,
			"{reason:?}"
		);
	}
}

#[test]
fn macros_and_encrypted_archives_have_their_own_setting_capped_by_the_mode() {
	use ContentAction::{Allow, Flag, Quarantine};
	let strict = policy(AttachmentMode::Reject, Quarantine, Flag);
	assert_eq!(action(&strict, &[Reason::Macro]), Action::Quarantine);
	assert_eq!(action(&strict, &[Reason::EncryptedArchive]), Action::Flag);
	let capped = policy(AttachmentMode::Flag, Quarantine, Quarantine);
	assert_eq!(action(&capped, &[Reason::Macro]), Action::Flag);
	let lenient = policy(AttachmentMode::Quarantine, Allow, Allow);
	let decision = lenient.decide(&report(&[Reason::Macro, Reason::EncryptedArchive]));
	assert_eq!(decision.action, Action::Deliver);
	assert!(decision.reasons.is_empty());
	assert_eq!(decision.header(), None);
}

#[test]
fn the_strongest_reason_wins_and_every_acting_reason_is_listed() {
	use ContentAction::{Allow, Flag};
	let policy = policy(AttachmentMode::Reject, Allow, Flag);
	let decision = policy.decide(&report(&[
		Reason::DangerousExtension,
		Reason::Macro,
		Reason::EncryptedArchive,
	]));
	assert_eq!(decision.action, Action::Reject);
	assert_eq!(
		decision.reasons,
		vec![Reason::DangerousExtension, Reason::EncryptedArchive]
	);
	assert_eq!(
		decision.header().as_deref(),
		Some("X-Epistle-Attachment-Warning: dangerous-extension, encrypted-archive\r\n")
	);
}

#[test]
fn stamping_replaces_a_header_the_sender_wrote() {
	let decision = Decision {
		action: Action::Flag,
		reasons: vec![Reason::Macro],
	};
	let mut data = b"Subject: s\r\nX-Epistle-Attachment-Warning: none\r\n\
		x-epistle-attachment-warning: clean\r\n\r\nbody\r\n"
		.to_vec();
	decision.stamp(&mut data);
	assert_eq!(
		String::from_utf8(data).expect("ascii"),
		"X-Epistle-Attachment-Warning: macro\r\nSubject: s\r\n\r\nbody\r\n"
	);
}

#[test]
fn a_real_check_runs_the_inspection() {
	let policy = policy(
		AttachmentMode::Quarantine,
		ContentAction::Flag,
		ContentAction::Flag,
	);
	let raw = crate::antispam::attachments::corpus::message(&[
		crate::antispam::attachments::corpus::attachment(
			"Content-Type: application/pdf; name=\"factura.pdf.exe\"",
			&crate::antispam::attachments::corpus::pe(),
		),
	]);
	let (_, decision) = policy.check(&raw);
	assert_eq!(decision.action, Action::Quarantine);
	assert!(decision.reasons.contains(&Reason::DoubleExtension));
}
