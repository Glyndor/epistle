//! Records for the evidence tests. Addresses use the reserved example
//! domains; nothing here is a credential.

use uuid::Uuid;

use super::MailClass;
use super::record::{Accepted, Entry, Outcome, OutcomeKind, Retention, RetentionMode};

/// An acceptance numbered `n`, retained `days`.
pub(crate) fn accepted_for(n: u32, days: u32) -> Entry {
	Entry::Accepted(Accepted {
		spool_id: Uuid::from_u128(u128::from(n)),
		account: "notices".into(),
		tenant: None,
		class: MailClass::Transactional,
		from: "notices@example.org".into(),
		recipients: vec![format!("student{n}@example.net")],
		message_id: Some(format!("<{n}@example.org>")),
		date: Some("Wed, 14 Oct 2026 10:00:00 +0000".into()),
		subject: Some(format!("Notice {n}")),
		sha256: "ab".repeat(32),
		size: 1000 + u64::from(n),
		retention: Retention {
			mode: RetentionMode::Metadata,
			days,
		},
	})
}

/// An acceptance numbered `n`, retained a year.
pub(crate) fn accepted(n: u32) -> Entry {
	accepted_for(n, 365)
}

/// A delivered outcome for the acceptance numbered `n`.
pub(crate) fn delivered(n: u32) -> Entry {
	Entry::Outcome(Outcome {
		spool_id: Uuid::from_u128(u128::from(n)),
		class: MailClass::Transactional,
		recipient: format!("student{n}@example.net"),
		result: OutcomeKind::Delivered,
		attempt: 1,
		remote: Some("mx.example.net".into()),
		reply: Some("250 2.0.0 OK queued as 1".into()),
		tls: None,
		dane: false,
		mta_sts: None,
		retain_days: 365,
	})
}

/// Epoch seconds at `hour` on day `day` (days since 1970-01-01).
pub(crate) fn at(day: i64, hour: u64) -> u64 {
	u64::try_from(day).expect("positive day") * 86_400 + hour * 3600
}
