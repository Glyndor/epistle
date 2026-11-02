use super::*;
use crate::test_fixtures::fresh_secret;

const OUR: &str = "relay.example";
const NOW: u64 = 19_000;
const AGE: u64 = 14;

fn local_of(address: &str) -> String {
	address.split_once('@').expect("an address").0.to_string()
}

fn srs() -> Srs {
	Srs::new(fresh_secret().as_bytes())
}

#[test]
fn a_domain_with_its_own_secret_names_itself_and_round_trips() {
	let keys = SrsKeys::default().with_domain("a.example", srs(), None);
	let address = keys
		.forward("A.Example", ("alice", "origin.example"), OUR, NOW)
		.expect("signed");
	assert!(address.starts_with("SRS0.a.example="), "{address}");
	assert!(address.ends_with("@relay.example"), "{address}");
	let back = keys.reverse(&local_of(&address), NOW, AGE).expect("valid");
	assert_eq!(back, ("alice".into(), "origin.example".into()));
}

#[test]
fn a_domain_without_one_gets_the_address_the_server_always_made() {
	let secret = fresh_secret();
	let keys = SrsKeys::global_only(Srs::new(secret.as_bytes()));
	let address = keys
		.forward("a.example", ("alice", "origin.example"), OUR, NOW)
		.expect("signed");
	// Byte for byte what `Srs::forward` made before domains had secrets.
	let legacy = Srs::new(secret.as_bytes()).forward("alice", "origin.example", OUR, NOW);
	assert_eq!(address, legacy);
	assert!(address.starts_with("SRS0="), "{address}");
}

#[test]
fn an_address_made_with_the_server_wide_secret_still_verifies_after_the_split() {
	let global = fresh_secret();
	let before = SrsKeys::global_only(Srs::new(global.as_bytes()));
	let in_flight = before
		.forward("a.example", ("alice", "origin.example"), OUR, NOW)
		.expect("signed");
	// The operator split: a.example has its own secret now, the global stays.
	let after = SrsKeys::default()
		.with_global(Srs::new(global.as_bytes()))
		.with_domain("a.example", srs(), None);
	let back = after.reverse(&local_of(&in_flight), NOW + 2, AGE);
	assert_eq!(back, Some(("alice".into(), "origin.example".into())));
	// New mail from a.example is signed with its own secret from here on.
	let fresh = after
		.forward("a.example", ("alice", "origin.example"), OUR, NOW + 2)
		.expect("signed");
	assert!(fresh.starts_with("SRS0.a.example="), "{fresh}");
}

#[test]
fn one_domains_address_does_not_verify_as_another() {
	let keys = SrsKeys::default()
		.with_domain("a.example", srs(), None)
		.with_domain("b.example", srs(), None);
	let address = keys
		.forward("a.example", ("alice", "origin.example"), OUR, NOW)
		.expect("signed");
	let local = local_of(&address);
	// Retag the address as b.example's: b's secret did not sign it.
	let forged = local.replacen("SRS0.a.example=", "SRS0.b.example=", 1);
	assert_ne!(forged, local);
	assert!(keys.reverse(&forged, NOW, AGE).is_none());
	assert!(keys.reverse(&local, NOW, AGE).is_some());
}

#[test]
fn the_hosted_domain_is_part_of_what_is_signed_even_under_one_secret() {
	// The configuration refuses two domains with the same secret, but the
	// signature must not depend on that: an address for a.example is not
	// one for b.example under identical keys.
	let secret = fresh_secret();
	let one = Srs::new(secret.as_bytes());
	let address = one.forward_for("a.example", ("alice", "origin.example"), OUR, NOW);
	let local = local_of(&address);
	assert!(one.reverse_for("a.example", &local, NOW, AGE).is_some());
	assert!(one.reverse_for("b.example", &local, NOW, AGE).is_none());
	let retagged = local.replacen("SRS0.a.example=", "SRS0.b.example=", 1);
	assert!(one.reverse_for("b.example", &retagged, NOW, AGE).is_none());
}

#[test]
fn a_domain_address_is_not_accepted_by_the_server_wide_secret() {
	let global = fresh_secret();
	let own = Srs::new(global.as_bytes());
	// The same bytes as the global, to prove the scope and not the key
	// is what separates them.
	let keys = SrsKeys::global_only(Srs::new(global.as_bytes()));
	let address = own.forward_for("a.example", ("alice", "origin.example"), OUR, NOW);
	assert!(keys.reverse(&local_of(&address), NOW, AGE).is_none());
	// And the legacy address carries no domain to pick a secret by.
	let legacy = own.forward("alice", "origin.example", OUR, NOW);
	let split = SrsKeys::default().with_domain("a.example", Srs::new(global.as_bytes()), None);
	assert!(split.reverse(&local_of(&legacy), NOW, AGE).is_none());
}

#[test]
fn a_rotated_secret_keeps_verifying_what_it_signed() {
	let old = fresh_secret();
	let before = SrsKeys::default().with_domain("a.example", Srs::new(old.as_bytes()), None);
	let in_flight = before
		.forward("a.example", ("alice", "origin.example"), OUR, NOW)
		.expect("signed");
	let after = SrsKeys::default().with_domain("a.example", srs(), Some(Srs::new(old.as_bytes())));
	assert!(after.reverse(&local_of(&in_flight), NOW + 1, AGE).is_some());
	let made_now = after
		.forward("a.example", ("alice", "origin.example"), OUR, NOW + 1)
		.expect("signed");
	assert!(before.reverse(&local_of(&made_now), NOW + 1, AGE).is_none());
	// Without the previous secret the old address no longer verifies.
	let dropped = SrsKeys::default().with_domain("a.example", srs(), None);
	assert!(
		dropped
			.reverse(&local_of(&in_flight), NOW + 1, AGE)
			.is_none()
	);
}

#[test]
fn an_address_for_an_unknown_domain_or_without_any_secret_is_refused() {
	let keys = SrsKeys::default().with_domain("a.example", srs(), None);
	let other = Srs::new(fresh_secret().as_bytes());
	let stranger = other.forward_for("c.example", ("alice", "origin.example"), OUR, NOW);
	assert!(keys.reverse(&local_of(&stranger), NOW, AGE).is_none());
	assert!(
		SrsKeys::default()
			.forward("a.example", ("alice", "origin.example"), OUR, NOW)
			.is_none()
	);
	assert!(keys.reverse("SRS0.=x=y=z=w", NOW, AGE).is_none());
	assert!(keys.reverse("SRS0.a.example", NOW, AGE).is_none());
}

#[test]
fn an_expired_domain_address_is_refused() {
	let keys = SrsKeys::default().with_domain("a.example", srs(), None);
	let address = keys
		.forward("a.example", ("alice", "origin.example"), OUR, NOW)
		.expect("signed");
	assert!(
		keys.reverse(&local_of(&address), NOW + AGE + 1, AGE)
			.is_none()
	);
}

#[test]
fn generated_secrets_are_long_and_distinct() {
	let one = generate_secret().expect("entropy");
	let two = generate_secret().expect("entropy");
	assert_eq!(one.len(), 43);
	assert_ne!(one, two);
}
