//! Destination policy and cancellable resolution regressions.

use super::*;

/// Global destinations on the standard port: what the probe uses unless the
/// operator opts in.
const POLICY_GLOBAL: Policy = Policy {
	allow_private: false,
	allowed_ports: Vec::new(),
};

/// The private-network opt-in on its own. It grants addresses, never ports.
fn private(allowed_ports: &[u16]) -> Policy {
	Policy {
		allow_private: true,
		allowed_ports: allowed_ports.to_vec(),
	}
}

#[tokio::test]
async fn review_rejects_the_whole_dns_answer_before_selecting_an_address() {
	for bad in [
		"127.0.0.1",
		"10.0.0.1",
		"169.254.0.1",
		"::1",
		"fc00::1",
		"fe80::1",
		"ff02::1",
		"::",
		"255.255.255.255",
		"::ffff:10.0.0.1",
	] {
		for reverse in [false, true] {
			let mut answer = vec!["1.1.1.1".parse().unwrap(), bad.parse().unwrap()];
			if reverse {
				answer.reverse();
			}
			let result = resolve_with(
				"clock.example",
				123,
				123,
				&POLICY_GLOBAL,
				Instant::now() + Duration::from_secs(2),
				async { Ok(answer) },
			)
			.await;
			assert!(
				matches!(result, Err(ProbeError::Dial(_))),
				"accepted {bad}: {result:?}"
			);
		}
	}
}

#[tokio::test]
async fn review_private_opt_in_preserves_the_validated_socket_address() {
	for ip in [
		"127.0.0.1",
		"10.0.0.1",
		"169.254.0.1",
		"::1",
		"fc00::1",
		"fe80::1",
	] {
		let result = resolve_with(
			"internal.example",
			6379,
			123,
			&private(&[6379]),
			Instant::now() + Duration::from_secs(2),
			async { Ok(vec![ip.parse().unwrap()]) },
		)
		.await
		.unwrap();
		assert_eq!(result, SocketAddr::new(ip.parse().unwrap(), 6379));
	}
	for ip in [
		"224.0.0.1",
		"255.255.255.255",
		"0.0.0.0",
		"ff02::1",
		"::",
		"::ffff:224.0.0.1",
		"::ffff:0.0.0.0",
		"::ffff:255.255.255.255",
	] {
		let result = resolve_with(
			"internal.example",
			123,
			123,
			&private(&[]),
			Instant::now() + Duration::from_secs(2),
			async { Ok(vec![ip.parse().unwrap()]) },
		)
		.await;
		assert!(result.is_err(), "accepted {ip}");
	}
}

#[test]
fn review_slow_async_dns_does_not_survive_runtime_shutdown() {
	let started = Instant::now();
	let runtime = tokio::runtime::Runtime::new().unwrap();
	let result = runtime.block_on(resolve_with(
		"slow.example",
		123,
		123,
		&POLICY_GLOBAL,
		Instant::now() + Duration::from_millis(40),
		async {
			tokio::time::sleep(Duration::from_secs(1)).await;
			Ok(vec!["1.1.1.1".parse().unwrap()])
		},
	));
	drop(runtime);
	assert_eq!(result, Err(ProbeError::Timeout));
	assert!(
		started.elapsed() < Duration::from_millis(300),
		"{:?}",
		started.elapsed()
	);
}

#[tokio::test]
async fn review_dns_has_its_own_deadline_and_rejects_an_empty_answer() {
	let result = resolve_with(
		"slow.example",
		123,
		123,
		&POLICY_GLOBAL,
		Instant::now() + Duration::from_secs(2),
		async {
			tokio::time::sleep(Duration::from_secs(1)).await;
			Ok(vec!["1.1.1.1".parse().unwrap()])
		},
	)
	.await;
	assert_eq!(result, Err(ProbeError::Timeout));
	let result = resolve_with(
		"empty.example",
		123,
		123,
		&POLICY_GLOBAL,
		Instant::now() + Duration::from_secs(2),
		async { Ok(vec![]) },
	)
	.await;
	assert!(matches!(result, Err(ProbeError::Dial(_))));
}

#[test]
fn review_udp_bind_matches_the_validated_address_family() {
	for remote in ["1.1.1.1:123", "[2606:4700:4700::1111]:123"] {
		let remote: SocketAddr = remote.parse().unwrap();
		let local = bind_address(remote);
		assert_eq!(local.is_ipv4(), remote.is_ipv4());
		assert!(local.ip().is_unspecified());
		assert_eq!(local.port(), 0);
	}
}

#[tokio::test]
async fn review_default_adapter_entry_points_refuse_internal_destinations() {
	use crate::clock::external::Source;
	use crate::clock::external::adapter::{ke_then_ntp, plain_ntp};
	for result in [
		plain_ntp(&Source::ntp("127.0.0.1"), Duration::from_secs(1)).await,
		ke_then_ntp(&Source::nts("::1"), Duration::from_secs(1)).await,
	] {
		match result {
			Err(ProbeError::Dial(why)) => assert!(why.contains("address is not allowed"), "{why}"),
			other => panic!("expected destination policy rejection, got {other:?}"),
		}
	}
}

#[test]
fn review_scoped_ipv6_is_rejected_clearly_even_with_opt_in() {
	for host in ["fe80::1%1", "fe80::1%eth0", "[fe80::1%1]"] {
		for allow in [false, true] {
			let policy = if allow {
				private(&[])
			} else {
				POLICY_GLOBAL.clone()
			};
			let result = validate_host(host, 123, 123, &policy);
			assert!(result.is_err(), "accepted unsupported zone {host}");
			let error = result.unwrap_err();
			assert!(
				error.contains("IPv6 zone identifiers are not supported"),
				"{error}"
			);
		}
	}
}

#[test]
fn review_non_global_destinations_require_opt_in() {
	for text in [
		"100.64.0.1",
		"100.127.255.255",
		"0.1.2.3",
		"192.0.0.9",
		"192.0.2.1",
		"198.51.100.1",
		"203.0.113.1",
		"198.18.0.1",
		"198.19.255.255",
		"240.0.0.1",
		"2001:db8::1",
		"fec0::1",
		"100::1",
		"2001:2::1",
		"3fff::1",
	] {
		let ip = text.parse().unwrap();
		assert!(validate_ip(ip, &POLICY_GLOBAL).is_err(), "accepted {text}");
		assert!(
			validate_ip(ip, &private(&[])).is_ok(),
			"opt-in rejected {text}"
		);
	}
}

#[test]
fn review_embedded_ipv4_obeys_both_destination_policies() {
	for prefix in ["::ffff:", "::", "64:ff9b::"] {
		for (payload, allowed_with_opt_in) in [
			("127.0.0.1", true),
			("100.64.0.1", true),
			("192.0.2.1", true),
			("224.0.0.1", false),
			("255.255.255.255", false),
			("0.0.0.0", false),
		] {
			let text = format!("{prefix}{payload}");
			let ip = text.parse().unwrap();
			assert!(validate_ip(ip, &POLICY_GLOBAL).is_err(), "accepted {text}");
			assert_eq!(
				validate_ip(ip, &private(&[])).is_ok(),
				allowed_with_opt_in,
				"{text}"
			);
		}
	}
	for (text, allowed_with_opt_in) in [
		("2002:7f00:1::1", true),
		("2002:6440:1::1", true),
		("2002:c000:201::1", true),
		("2002:e000:1::1", false),
		("2002:ffff:ffff::1", false),
		("2002:0:0::1", false),
	] {
		let ip = text.parse().unwrap();
		assert!(validate_ip(ip, &POLICY_GLOBAL).is_err(), "accepted {text}");
		assert_eq!(
			validate_ip(ip, &private(&[])).is_ok(),
			allowed_with_opt_in,
			"{text}"
		);
	}
}

/// The clock refuses a non-global destination with the same classifier the
/// `public_ipv6` validation uses, and the two must agree on every form that
/// carries an IPv4 payload: the clock took the forms from its own list and the
/// list in the classifier could grow without it.
#[test]
fn review_destination_policy_follows_the_shared_classifier_on_every_form() {
	for text in [
		"64:ff9b::7f00:1",
		"64:ff9b::a00:1",
		"64:ff9b::a9fe:a9fe",
		"2002:7f00:1::1",
		"2002:c000:201::1",
		"::127.0.0.1",
		"::ffff:10.0.0.1",
		"64:ff9b:1::1",
		"64:ff9b::808:808",
		"::ffff:1.1.1.1",
		"2606:4700:4700::1111",
	] {
		let ip: Ipv6Addr = text.parse().unwrap();
		assert_eq!(
			validate_ip(ip.into(), &POLICY_GLOBAL).is_err(),
			crate::config::non_global_ipv6_reason(ip).is_some(),
			"{text}: the clock destination and the classifier disagree"
		);
	}
}

#[tokio::test]
async fn review_unusual_numeric_names_cannot_bypass_resolved_address_policy() {
	for host in [
		"0x7f.1",
		"2130706433",
		"127.1",
		"0177.0.0.1",
		"127.000.000.001",
	] {
		let result = resolve_with(
			host,
			123,
			123,
			&POLICY_GLOBAL,
			Instant::now() + Duration::from_secs(1),
			async { Ok(vec!["127.0.0.1".parse().unwrap()]) },
		)
		.await;
		assert!(
			matches!(result, Err(ProbeError::Dial(_))),
			"{host}: {result:?}"
		);
	}
}

#[tokio::test]
async fn review_special_ranges_in_mixed_dns_answers_are_rejected_in_both_orders() {
	for text in [
		"100.64.0.1",
		"198.18.0.1",
		"2001:db8::1",
		"64:ff9b::192.0.2.1",
		"2002:6440:1::1",
	] {
		for reverse in [false, true] {
			let mut addresses = vec!["1.1.1.1".parse().unwrap(), text.parse().unwrap()];
			if reverse {
				addresses.reverse();
			}
			let result = resolve_with(
				"clock.example",
				123,
				123,
				&POLICY_GLOBAL,
				Instant::now() + Duration::from_secs(1),
				async { Ok(addresses) },
			)
			.await;
			assert!(result.is_err(), "accepted {text}, reverse={reverse}");
		}
	}
}

#[test]
fn review_global_destinations_and_embedded_global_ipv4_remain_allowed() {
	for text in [
		"1.1.1.1",
		"2606:4700:4700::1111",
		"::ffff:1.1.1.1",
		"64:ff9b::1.1.1.1",
	] {
		assert!(
			validate_ip(text.parse().unwrap(), &POLICY_GLOBAL).is_ok(),
			"{text}"
		);
		assert!(
			validate_ip(text.parse().unwrap(), &private(&[])).is_ok(),
			"{text}"
		);
	}
}

/// One classification decides, so a transition address is judged as the IPv6
/// address it is: 6to4 and the deprecated compatible form are refused by
/// default even when the payload they carry is a global IPv4, because that is
/// what the `public_ipv6` classifier says about them.
#[test]
fn review_transition_destinations_follow_the_shared_classifier_without_the_opt_in() {
	for text in [
		"2002:808:808::",
		"2002:101:101::1",
		"::8.8.8.8",
		"::1.1.1.1",
	] {
		let ip: Ipv6Addr = text.parse().unwrap();
		assert_eq!(
			validate_ip(ip.into(), &POLICY_GLOBAL).is_err(),
			crate::config::non_global_ipv6_reason(ip).is_some(),
			"{text}: the clock and the classifier disagree"
		);
		assert!(
			validate_ip(ip.into(), &POLICY_GLOBAL).is_err(),
			"{text} carries a global payload but is still a transition address"
		);
		assert!(validate_ip(ip.into(), &private(&[])).is_ok(), "{text}");
	}
}

#[tokio::test]
async fn review_scoped_ipv6_is_rejected_before_lookup() {
	let result = resolve_with(
		"fe80::1%eth0",
		123,
		123,
		&private(&[]),
		Instant::now() + Duration::from_secs(1),
		async {
			panic!("unsupported zone must not reach DNS");
		},
	)
	.await;
	assert!(
		matches!(result, Err(ProbeError::Dial(why)) if why.contains("IPv6 zone identifiers are not supported"))
	);
}

#[tokio::test]
async fn default_policy_accepts_the_port_a_default_operator_publishes() {
	// The policy a fresh install builds from its default configuration.
	let defaults = crate::clock::external::source::ClockExternal::default();
	assert!(defaults.validate().is_ok());
	let policy = defaults.policy();
	let stop = || Instant::now() + Duration::from_secs(2);
	let address = || async { Ok(vec!["1.1.1.1".parse().unwrap()]) };
	let ok = resolve_with("nts.netnod.se", 4123, 123, &policy, stop(), address()).await;
	assert_eq!(ok, Ok(SocketAddr::new("1.1.1.1".parse().unwrap(), 4123)));
	// A hostile key-exchange answer cannot aim the poll at a sensitive port.
	for port in [22u16, 25, 5432, 6379, 11211, 4460] {
		let bad = resolve_with("evil.example", port, 123, &policy, stop(), address()).await;
		assert!(matches!(bad, Err(ProbeError::Dial(_))), "accepted {port}");
	}
	// The extra port is for the NTP side only, never for the key exchange.
	let ke = resolve_with("evil.example", 4123, 4460, &policy, stop(), address()).await;
	assert!(matches!(ke, Err(ProbeError::Dial(_))));
}
