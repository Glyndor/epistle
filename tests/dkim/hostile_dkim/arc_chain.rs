//! Instance, cv, completeness, and the 50-hop inclusive boundary.

use super::harness::*;
use super::support::*;
use epistle::arc::chain::{self, ChainError, ChainValidation::*};

fn malformed(raw: Vec<u8>, expected: ChainError) {
	let inspected = raw.clone();
	assert_eq!(bounded(move || chain::extract(&inspected)), Err(expected));
	assert_eq!(arc(raw, Dns::arc("arc-ed-1")), (Fail, 0));
}

#[test]
fn no_arc_is_none() {
	assert_eq!(arc(message("signer-raw"), Dns::arc("arc-ed-1")), (None, 0));
}

#[test]
fn two_external_hops_pass() {
	let name = "arc-ed-2";
	assert_eq!(arc(message(name), Dns::arc(name)), (Pass, 3));
}

#[test]
fn fifty_external_hops_are_inclusive() {
	let name = "arc-ed-50";
	let raw = message(name);
	let inspected = raw.clone();
	let instances = bounded(move || chain::extract(&inspected))
		.unwrap()
		.unwrap();
	assert_eq!(instances.len(), 50);
	assert_eq!(instances.first().unwrap().instance, 1);
	assert_eq!(instances.last().unwrap().instance, 50);
	assert_eq!(arc(raw, Dns::arc(name)), (Pass, 51));
}

#[test]
fn fifty_first_instance_is_rejected_before_crypto() {
	let raw = replace(&message("arc-ed-50"), "i=50;", "i=51;");
	malformed(raw, ChainError::BadInstance);
}

#[test]
fn out_of_sequence_instance_creates_a_gap() {
	let raw = String::from_utf8(message("arc-ed-2"))
		.unwrap()
		.replace("i=1;", "i=3;");
	malformed(raw.into_bytes(), ChainError::NonContiguous);
}

#[test]
fn repeated_instance_is_rejected() {
	let raw = String::from_utf8(message("arc-ed-2"))
		.unwrap()
		.replace("i=2;", "i=1;");
	malformed(raw.into_bytes(), ChainError::Duplicate);
}

#[test]
fn missing_member_is_incomplete() {
	let raw = String::from_utf8(message("arc-ed-1")).unwrap();
	let raw = raw
		.split_inclusive("\r\n")
		.filter(|line| !line.starts_with("ARC-Authentication-Results:"))
		.collect::<String>();
	malformed(raw.into_bytes(), ChainError::Incomplete);
}

#[test]
fn first_cv_must_be_none() {
	let name = "arc-cv-first-pass";
	assert_eq!(arc(message(name), Dns::arc(name)), (Fail, 0));
}

#[test]
fn later_cv_must_be_pass() {
	let name = "arc-cv-later-none";
	assert_eq!(arc(message(name), Dns::arc(name)), (Fail, 0));
}

#[test]
fn cv_fail_stops_the_chain() {
	let name = "arc-ed-2";
	let raw = replace(&message(name), "cv=pass", "cv=fail");
	assert_eq!(arc(raw, Dns::arc(name)), (Fail, 0));
}

#[test]
fn physical_set_order_is_independent_of_instance_hash_order() {
	let name = "arc-ed-2";
	let raw = message(name);
	let wire = std::str::from_utf8(&raw).unwrap();
	let lines: Vec<_> = wire.split_inclusive("\r\n").collect();
	assert!(lines[0].starts_with("ARC-Seal: i=2;"));
	let reordered = lines[3..6].concat() + &lines[..3].concat() + &lines[6..].concat();
	assert_eq!(arc(reordered.into_bytes(), Dns::arc(name)), (Pass, 3));
}
