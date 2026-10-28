//! The Author Domain DMARC evaluates must be the one a reader sees: no
//! second From field hidden behind `From :`, no domain picked out of a
//! comment, no last-address-wins on a From listing several domains.

use super::*;

#[test]
fn from_with_space_before_colon_is_a_second_from_field() {
	let raw = b"From: eve@sender.example\r\nFrom : ceo@bank.example\r\n\r\nbody";
	assert_eq!(from_domain(raw), None);
}

#[test]
fn an_address_in_a_comment_is_not_the_author() {
	let raw = b"From: ceo@bank.example (eve@sender.example)\r\n\r\nbody";
	assert_eq!(from_domain(raw), Some("bank.example".to_string()));
}

#[test]
fn a_from_naming_two_domains_has_no_single_author_domain() {
	let raw = b"From: ceo@bank.example, eve@sender.example\r\n\r\nbody";
	assert_eq!(from_domain(raw), None);
	let raw = b"From: <ceo@bank.example>, Eve <eve@sender.example>\r\n\r\nbody";
	assert_eq!(from_domain(raw), None);
}

#[test]
fn a_from_naming_one_domain_twice_keeps_it() {
	let raw = b"From: a@bank.example, b@Bank.Example\r\n\r\nbody";
	assert_eq!(from_domain(raw), Some("bank.example".to_string()));
}
