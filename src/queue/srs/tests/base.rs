use super::*;

const SECRET: &[u8] = b"a shared srs secret";
const OUR: &str = "relay.example";

#[test]
fn forward_then_reverse_recovers_sender() {
	let srs = Srs::new(SECRET);
	let addr = srs.forward("alice", "example.org", OUR, 19_000);
	assert!(addr.starts_with("SRS0="));
	assert!(addr.ends_with("@relay.example"));
	let local = addr.split_once('@').unwrap().0;
	let (recovered_local, recovered_domain) = srs.reverse(local, 19_000, 7).expect("valid");
	assert_eq!(recovered_local, "alice");
	assert_eq!(recovered_domain, "example.org");
}

#[test]
fn tampered_address_is_rejected() {
	let srs = Srs::new(SECRET);
	let addr = srs.forward("alice", "example.org", OUR, 19_000);
	let local = addr.split_once('@').unwrap().0;
	// Swap the source domain without re-signing.
	let forged = local.replace("example.org", "evil.example");
	assert!(srs.reverse(&forged, 19_000, 7).is_none());
}

#[test]
fn wrong_secret_does_not_validate() {
	let signer = Srs::new(SECRET);
	let addr = signer.forward("alice", "example.org", OUR, 19_000);
	let local = addr.split_once('@').unwrap().0;
	let other = Srs::new(b"different secret");
	assert!(other.reverse(local, 19_000, 7).is_none());
}

#[test]
fn expired_timestamp_is_rejected() {
	let srs = Srs::new(SECRET);
	let addr = srs.forward("alice", "example.org", OUR, 19_000);
	let local = addr.split_once('@').unwrap().0;
	// Ten days later, with a seven-day window.
	assert!(srs.reverse(local, 19_010, 7).is_none());
	// Still valid five days later.
	assert!(srs.reverse(local, 19_005, 7).is_some());
}

#[test]
fn local_part_with_equals_survives() {
	let srs = Srs::new(SECRET);
	let addr = srs.forward("a=b+c", "example.org", OUR, 19_000);
	let local = addr.split_once('@').unwrap().0;
	let (recovered, _) = srs.reverse(local, 19_000, 7).expect("valid");
	assert_eq!(recovered, "a=b+c");
}

#[test]
fn non_srs_address_is_ignored() {
	let srs = Srs::new(SECRET);
	assert!(srs.reverse("plain", 19_000, 7).is_none());
}
