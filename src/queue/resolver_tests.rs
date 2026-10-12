//! Choosing the exchangers of a recipient domain from its MX records.

use super::*;

#[test]
fn exchangers_follow_the_records_or_the_implicit_mx() {
	let records = vec![
		(10, "mx1.example.net.".to_string()),
		(20, "mx2.example.net.".to_string()),
	];
	assert_eq!(
		exchangers_from("example.net", records),
		Ok(vec![
			"mx1.example.net".to_string(),
			"mx2.example.net".to_string()
		])
	);
	assert_eq!(
		exchangers_from("example.net", Vec::new()),
		Ok(vec!["example.net".to_string()])
	);
}

#[test]
fn a_null_mx_refuses_mail_at_once() {
	// RFC 7505: a single MX of preference 0 for the root name means the
	// domain accepts no mail; the sender gets 5.1.10 without retries.
	let refused = exchangers_from("nomail.example", vec![(0, ".".to_string())]);
	assert_eq!(
		refused,
		Err(DeliveryError::Permanent(
			"556 5.1.10 nomail.example accepts no mail (null MX)".to_string()
		))
	);
	let verdict = crate::queue::reply::classify_reason(
		match &refused {
			Err(DeliveryError::Permanent(reason)) => reason,
			_ => "",
		},
		true,
	);
	assert_eq!(
		verdict.class,
		crate::queue::reply::FailureClass::InvalidAddress
	);
	assert!(verdict.permanent && verdict.suppress);
}

#[test]
fn a_root_exchange_next_to_real_ones_is_skipped() {
	let records = vec![(0, ".".to_string()), (10, "mx.example.net.".to_string())];
	assert_eq!(
		exchangers_from("example.net", records),
		Ok(vec!["mx.example.net".to_string()])
	);
}
