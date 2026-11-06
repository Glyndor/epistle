//! Hostile local parts handed to the SRS reverse path. The local part comes from the
//! RCPT TO of an unauthenticated bounce, so it is attacker text: it must never panic
//! the session and never reverse unless the hash is ours.

use super::*;

const NOW: u64 = 19_000;
const SECRET: &[u8] = b"a shared srs secret";
const OUR: &str = "relay.example";

fn reverse_all(locals: &[String]) {
	let srs = Srs::new(SECRET);
	for local in locals {
		assert!(srs.reverse(local, NOW, 7).is_none(), "{local:?}");
		assert!(
			srs.reverse_for("example.org", local, NOW, 7).is_none(),
			"{local:?}"
		);
	}
}

#[test]
fn a_multibyte_character_across_the_prefix_boundary_is_refused_not_a_panic() {
	// "SRS0=" is five bytes; a two byte character at bytes 4..6 puts a char boundary
	// inside the prefix. Slicing there panics unless the prefix test is boundary safe.
	reverse_all(&[
		"SRS0\u{e9}=aaaa=AB=example.org=alice".to_string(),
		"SRS\u{1f600}0=aaaa=AB=example.org=alice".to_string(),
		"SRS0.\u{e9}=x".to_string(),
		"SRS0.exam\u{e9}ple.org=aaaa=AB=example.org=alice".to_string(),
		"\u{1f600}\u{1f600}\u{1f600}".to_string(),
	]);
}

#[test]
fn truncated_and_empty_forms_are_refused() {
	reverse_all(&[
		String::new(),
		"SRS0".into(),
		"SRS0=".into(),
		"SRS0=aaaa".into(),
		"SRS0=aaaa=AB".into(),
		"SRS0=aaaa=AB=example.org".into(),
		"SRS0=aaaa=AB=example.org=".into(),
		"SRS0=aaaa=AB==alice".into(),
		"SRS0.=aaaa=AB=example.org=alice".into(),
		"SRS0.example.org".into(),
		"SRS0.example.org=".into(),
		"====".into(),
	]);
}

#[test]
fn an_enormous_local_part_is_refused_without_work_proportional_to_a_secret() {
	let big = format!("SRS0=aaaa=AB=example.org={}", "x".repeat(1 << 20));
	reverse_all(&[
		big,
		"=".repeat(1 << 20),
		format!("SRS0.{}=x", "a".repeat(1 << 16)),
	]);
}

#[test]
fn a_hash_cut_short_or_padded_is_not_a_match() {
	let srs = Srs::new(SECRET);
	let addr = srs.forward("alice", "example.org", OUR, NOW);
	let local = addr.split_once('@').unwrap().0;
	let (_, rest) = local.split_once('=').unwrap();
	let (hash, tail) = rest.split_once('=').unwrap();
	assert_eq!(hash.len(), 4);
	for forged in [
		format!("SRS0={}={tail}", &hash[..3]),
		format!("SRS0={hash}0={tail}"),
		format!("SRS0==={tail}"),
		format!("SRS0={}={tail}", hash.to_ascii_uppercase()),
	] {
		if forged == local {
			continue;
		}
		let reversed = srs.reverse(&forged, NOW, 7);
		let uppercase_only =
			forged.ends_with(tail) && forged[5..].starts_with(&hash.to_ascii_uppercase());
		assert!(
			reversed.is_none() || uppercase_only,
			"{forged:?} -> {reversed:?}"
		);
	}
}

#[test]
fn an_address_for_one_hosted_domain_never_reverses_for_another_or_for_the_server() {
	let srs = Srs::new(SECRET);
	let addr = srs.forward_for("example.org", ("alice", "example.net"), OUR, NOW);
	let local = addr.split_once('@').unwrap().0;
	assert!(srs.reverse_for("example.org", local, NOW, 7).is_some());
	assert!(srs.reverse_for("example.com", local, NOW, 7).is_none());
	assert!(
		srs.reverse(local, NOW, 7).is_none(),
		"global path must refuse a hosted address"
	);
}

#[test]
fn a_future_or_ancient_timestamp_is_not_taken_for_fresh() {
	let srs = Srs::new(SECRET);
	let addr = srs.forward("alice", "example.net", OUR, NOW + 30);
	let local = addr.split_once('@').unwrap().0;
	assert!(srs.reverse(local, NOW, 7).is_none(), "30 days ahead");
	let old = srs.forward("alice", "example.net", OUR, NOW - 30);
	let local = old.split_once('@').unwrap().0;
	assert!(srs.reverse(local, NOW, 7).is_none(), "30 days old");
}
