//! Choosing the exchangers of a recipient domain from its MX records, and
//! the DNSSEC state of the answer (RFC 7672 section 2.2.1): DANE only for
//! hosts a secure answer named, and a bogus answer is a failure.

use hickory_resolver::proto::dnssec::Proof;

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

#[test]
fn an_answer_whose_every_record_validated_is_secure() {
	assert_eq!(
		mx_security([Proof::Secure, Proof::Secure]),
		Ok(MxSecurity::Secure)
	);
}

#[test]
fn an_unsigned_or_unanchored_answer_is_insecure() {
	for proofs in [
		vec![Proof::Insecure],
		vec![Proof::Indeterminate],
		vec![Proof::Secure, Proof::Insecure],
		vec![],
	] {
		assert_eq!(
			mx_security(proofs.clone()),
			Ok(MxSecurity::Insecure),
			"{proofs:?}"
		);
	}
}

#[test]
fn a_bogus_record_fails_the_lookup() {
	assert_eq!(
		mx_security([Proof::Secure, Proof::Bogus]),
		Err(crate::spf::DnsFailure::Temporary)
	);
}

#[test]
fn a_secure_denial_and_secure_addresses_make_a_secure_implicit_mx() {
	assert_eq!(
		implicit_mx_security(Proof::Secure, Proof::Secure),
		Ok(MxSecurity::Secure)
	);
}

#[test]
fn an_unsigned_side_makes_an_insecure_implicit_mx() {
	for (denial, address) in [
		(Proof::Insecure, Proof::Secure),
		(Proof::Secure, Proof::Insecure),
		(Proof::Indeterminate, Proof::Secure),
		(Proof::Secure, Proof::Indeterminate),
	] {
		assert_eq!(
			implicit_mx_security(denial, address),
			Ok(MxSecurity::Insecure),
			"{denial:?} {address:?}"
		);
	}
}

#[test]
fn a_bogus_denial_or_address_fails_the_implicit_mx() {
	for (denial, address) in [
		(Proof::Bogus, Proof::Secure),
		(Proof::Secure, Proof::Bogus),
		(Proof::Bogus, Proof::Insecure),
		(Proof::Insecure, Proof::Bogus),
	] {
		assert_eq!(
			implicit_mx_security(denial, address),
			Err(crate::spf::DnsFailure::Temporary),
			"{denial:?} {address:?}"
		);
	}
}

#[test]
fn a_set_of_proofs_is_as_strong_as_its_weakest_record() {
	assert_eq!(summarize([Proof::Secure, Proof::Secure]), Proof::Secure);
	assert_eq!(summarize([Proof::Secure, Proof::Insecure]), Proof::Insecure);
	assert_eq!(summarize([Proof::Insecure, Proof::Bogus]), Proof::Bogus);
	assert_eq!(summarize([Proof::Bogus, Proof::Secure]), Proof::Bogus);
	assert_eq!(summarize([]), Proof::Insecure);
}

/// Open `host`, except that the hosts in `hung` never answer.
fn opener(
	hung: &'static [&'static str],
) -> impl FnMut(&str) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<String>>>> {
	move |host: &str| {
		let host = host.to_string();
		Box::pin(async move {
			if hung.contains(&host.as_str()) {
				std::future::pending::<()>().await;
			}
			Ok(format!("stream to {host}"))
		})
	}
}

#[tokio::test(start_paused = true)]
async fn a_connect_that_times_out_moves_on_to_the_next_exchanger() {
	let hosts = vec!["mx1.example.net".to_string(), "mx2.example.net".to_string()];
	let started = tokio::time::Instant::now();
	let reached = first_reachable("example.net", &hosts, opener(&["mx1.example.net"])).await;
	assert_eq!(
		reached,
		Ok((
			"mx2.example.net".to_string(),
			"stream to mx2.example.net".to_string()
		))
	);
	assert_eq!(started.elapsed(), timeouts::CONNECT);
}

#[tokio::test(start_paused = true)]
async fn every_exchanger_timing_out_is_a_transient_failure() {
	let hosts = vec!["mx1.example.net".to_string(), "mx2.example.net".to_string()];
	let started = tokio::time::Instant::now();
	let reached = first_reachable(
		"example.net",
		&hosts,
		opener(&["mx1.example.net", "mx2.example.net"]),
	)
	.await;
	assert_eq!(
		reached,
		Err(DeliveryError::Transient(
			"connect to mx2.example.net:25 timed out after 30s".into()
		))
	);
	assert_eq!(started.elapsed(), timeouts::CONNECT * 2);
}

fn hosts(names: &[&str]) -> Vec<String> {
	names.iter().map(|name| name.to_string()).collect()
}

#[test]
fn the_next_exchanger_comes_after_the_last_one_tried() {
	let all = hosts(&["mx1.example.net", "mx2.example.net", "mx3.example.net"]);
	assert_eq!(
		candidates("example.net", all.clone(), None, &[]),
		Ok(all.clone())
	);
	assert_eq!(
		candidates(
			"example.net",
			all.clone(),
			None,
			&hosts(&["mx2.example.net"])
		),
		Ok(hosts(&["mx3.example.net"])),
		"mx1 failed to connect before mx2 answered, so it is not tried again"
	);
	assert_eq!(
		candidates(
			"example.net",
			all.clone(),
			None,
			&hosts(&["mx1.example.net", "mx2.example.net"])
		),
		Ok(hosts(&["mx3.example.net"]))
	);
	assert_eq!(
		candidates("example.net", all, None, &hosts(&["mx3.example.net"])),
		Err(DeliveryError::Transient(
			"no further exchanger for example.net".into()
		))
	);
}

#[test]
fn the_next_exchanger_is_still_one_the_policy_permits() {
	let policy = Policy {
		mode: crate::mtasts::Mode::Enforce,
		mx: vec!["mx1.example.net".into(), "mx3.example.net".into()],
		max_age: 86_400,
	};
	let all = hosts(&["mx1.example.net", "mx2.example.net", "mx3.example.net"]);
	assert_eq!(
		candidates(
			"example.net",
			all.clone(),
			Some(&policy),
			&hosts(&["mx1.example.net"])
		),
		Ok(hosts(&["mx3.example.net"]))
	);
	let unlisted = Policy {
		mx: vec!["other.example.org".into()],
		..policy
	};
	assert_eq!(
		candidates("example.net", all, Some(&unlisted), &[]),
		Err(DeliveryError::Transient(
			"no MTA-STS-permitted MX for example.net".into()
		))
	);
}

#[test]
fn a_domain_with_many_exchangers_is_tried_on_a_few() {
	let many: Vec<String> = (0..200).map(|n| format!("mx{n}.example.net")).collect();
	let first = candidates("example.net", many.clone(), None, &[]).expect("candidates");
	assert_eq!(first.len(), crate::queue::limits::MAX_EXCHANGERS);
	assert_eq!(
		candidates("example.net", many, None, &first[first.len() - 1..]),
		Err(DeliveryError::Transient(
			"no further exchanger for example.net".into()
		))
	);
}
