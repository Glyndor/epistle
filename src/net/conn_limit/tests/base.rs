use super::*;

fn ip(text: &str) -> IpAddr {
	text.parse().expect("address")
}

#[test]
fn a_client_cannot_hold_more_than_its_share() {
	let admission = Admission::new(100, 3);
	let peer = ip("203.0.113.9");
	let held: Vec<_> = (0..3)
		.map(|_| admission.admit(peer).expect("within the cap"))
		.collect();
	assert_eq!(admission.admit(peer).err(), Some(Refusal::ClientFull));
	assert!(
		admission.admit(ip("203.0.113.10")).is_ok(),
		"another client is not affected"
	);
	drop(held);
}

#[test]
fn a_refusal_for_the_client_does_not_keep_a_listener_place() {
	let admission = Admission::new(2, 1);
	let peer = ip("203.0.113.9");
	let _first = admission.admit(peer).expect("first");
	for _ in 0..10 {
		assert_eq!(admission.admit(peer).err(), Some(Refusal::ClientFull));
	}
	assert!(
		admission.admit(ip("203.0.113.10")).is_ok(),
		"the refused attempts left the second place free"
	);
}

#[test]
fn the_listener_cap_holds_across_clients() {
	let admission = Admission::new(2, 10);
	let _a = admission.admit(ip("203.0.113.1")).expect("a");
	let _b = admission.admit(ip("203.0.113.2")).expect("b");
	assert_eq!(
		admission.admit(ip("203.0.113.3")).err(),
		Some(Refusal::ListenerFull)
	);
}

#[test]
fn an_ipv6_client_is_counted_by_its_slash_64() {
	let admission = Admission::new(100, 2);
	let _a = admission.admit(ip("2001:db8:1:2::1")).expect("first");
	let _b = admission.admit(ip("2001:db8:1:2::2")).expect("second");
	assert_eq!(
		admission.admit(ip("2001:db8:1:2:ffff::7")).err(),
		Some(Refusal::ClientFull),
		"another address of the same /64 is the same client"
	);
	assert!(
		admission.admit(ip("2001:db8:1:3::1")).is_ok(),
		"the next /64 is another client"
	);
}

#[test]
fn an_ipv4_mapped_peer_is_the_same_client_as_its_ipv4_address() {
	let admission = Admission::new(100, 1);
	let _a = admission.admit(ip("203.0.113.9")).expect("plain");
	assert_eq!(
		admission.admit(ip("::ffff:203.0.113.9")).err(),
		Some(Refusal::ClientFull)
	);
}

#[test]
fn dropping_the_guard_gives_both_places_back() {
	let admission = Admission::new(1, 1);
	let peer = ip("203.0.113.9");
	let guard = admission.admit(peer).expect("first");
	assert_eq!(admission.held_by(peer), 1);
	drop(guard);
	assert_eq!(admission.held_by(peer), 0);
	assert!(admission.admit(peer).is_ok());
}

#[tokio::test]
async fn a_task_that_panics_still_gives_its_places_back() {
	let admission = Admission::new(1, 1);
	let peer = ip("203.0.113.9");
	let guard = admission.admit(peer).expect("first");
	let task = tokio::spawn(async move {
		let _guard = guard;
		panic!("connection task failed");
	});
	assert!(task.await.is_err());
	assert_eq!(admission.held_by(peer), 0);
	assert!(admission.admit(peer).is_ok());
}

#[tokio::test]
async fn a_task_that_is_aborted_still_gives_its_places_back() {
	let admission = Admission::new(1, 1);
	let peer = ip("203.0.113.9");
	let guard = admission.admit(peer).expect("first");
	let task = tokio::spawn(async move {
		let _guard = guard;
		std::future::pending::<()>().await;
	});
	tokio::task::yield_now().await;
	task.abort();
	let _ = task.await;
	assert_eq!(admission.held_by(peer), 0);
}

#[tokio::test]
async fn a_refused_peer_gets_the_reply_and_a_close() {
	use tokio::io::AsyncReadExt;
	let (mut client, server) = tokio::io::duplex(256);
	refuse(server, b"* BYE busy\r\n");
	let mut seen = Vec::new();
	client.read_to_end(&mut seen).await.expect("read");
	assert_eq!(seen, b"* BYE busy\r\n");
}

#[test]
fn excessive_listener_caps_are_clamped_before_admission() {
	for requested in [MAX_CONNECTIONS + 1, usize::MAX] {
		let admission = Admission::new(requested, 2);
		assert_eq!(admission.listener.available_permits(), MAX_CONNECTIONS);
		assert!(admission.admit(ip("203.0.113.9")).is_ok());
	}
	assert_eq!(connection_semaphore(7).available_permits(), 7);
}
