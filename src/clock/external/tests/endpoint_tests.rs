//! Destination policy and cancellable resolution regressions.

use super::*;

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
				false,
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
			true,
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
			true,
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
		false,
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
		false,
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
		false,
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
