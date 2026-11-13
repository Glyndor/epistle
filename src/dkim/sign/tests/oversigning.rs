//! Oversigning of absent fields, folded and repeated fields, and the signed header table.

use super::headers::{FIELDS, check, fixture, message, names};
use super::*;
use crate::dkim::DkimOutcome;
use crate::dkim::test_support::signature_headers;

#[tokio::test]
async fn absent_important_fields_are_oversigned_once() {
	let (signer, dns) = fixture(true);
	let raw = "From: alice@example.org\r\n\r\nbody\r\n";
	let signature = signer.sign("example.org", raw.as_bytes()).expect("sign");
	for list in signature_headers(signature.as_bytes())
		.iter()
		.map(|field| names(field))
	{
		for (name, _, oversigned) in FIELDS {
			let count = list
				.iter()
				.filter(|field| field.eq_ignore_ascii_case(name))
				.count();
			assert_eq!(
				count,
				usize::from(*oversigned) + usize::from(*name == "From"),
				"{name}"
			);
		}
	}
	check(&dns, &signature, raw, DkimOutcome::Pass).await;
	for (name, value, oversigned) in FIELDS {
		if *oversigned && *name != "From" {
			check(
				&dns,
				&signature,
				&format!("{name}: {value}\r\n{raw}"),
				DkimOutcome::Fail,
			)
			.await;
		}
	}
}

#[tokio::test]
async fn folded_mixed_case_fields_verify_after_equivalent_refolding() {
	let (signer, dns) = fixture(true);
	let raw = "fRoM: Alice\r\n\t<alice@example.org>\r\nrEpLy-To: Reply\r\n <reply@example.org>\r\nLiSt-UnSuBsCrIbE: \r\n\t<https://example.org/unsubscribe>\r\nlIsT-UnSuBsCrIbE-pOsT: List-Unsubscribe=One-Click\r\n\r\nbody\r\n";
	let signature = signer.sign("example.org", raw.as_bytes()).expect("sign");
	check(&dns, &signature, raw, DkimOutcome::Pass).await;
	let refolded = raw
		.replace("\r\n\t", " ")
		.replace("\r\n ", "\t")
		.replace("rEpLy-To", "REPLY-TO");
	check(&dns, &signature, &refolded, DkimOutcome::Pass).await;
	check(
		&dns,
		&signature,
		&raw.replace("reply@example.org", "other@example.org"),
		DkimOutcome::Fail,
	)
	.await;
}

#[tokio::test]
async fn repeated_fields_and_all_resent_names_are_signed_bottom_up() {
	let (signer, dns) = fixture(true);
	let mut raw = message();
	for name in [
		"Subject",
		"Sender",
		"rEsEnT-fRoM",
		"Resent-To",
		"Resent-Cc",
		"Resent-Date",
		"Resent-Message-ID",
		"Resent-Sender",
		"Resent-Custom",
	] {
		raw = format!("{name}: upper\r\n{name}: lower\r\n{raw}");
	}
	let signature = signer.sign("example.org", raw.as_bytes()).expect("sign");
	check(&dns, &signature, &raw, DkimOutcome::Pass).await;
	let resent = format!("Resent-From: next@example.org\r\nResent-Custom: next\r\n{raw}");
	check(&dns, &signature, &resent, DkimOutcome::Pass).await;
	for list in signature_headers(signature.as_bytes())
		.iter()
		.map(|field| names(field))
	{
		assert_eq!(list.iter().filter(|name| *name == "subject").count(), 4);
		assert_eq!(list.iter().filter(|name| *name == "sender").count(), 3);
	}
	for name in [
		"Subject",
		"Sender",
		"rEsEnT-fRoM",
		"Resent-To",
		"Resent-Cc",
		"Resent-Date",
		"Resent-Message-ID",
		"Resent-Sender",
		"Resent-Custom",
	] {
		for value in ["upper", "lower"] {
			let changed = raw.replace(&format!("{name}: {value}"), &format!("{name}: changed"));
			check(&dns, &signature, &changed, DkimOutcome::Fail).await;
		}
	}
}

#[tokio::test]
async fn transit_headers_are_excluded_and_can_change() {
	let (signer, dns) = fixture(true);
	// `X-Epistle` is the one `X-` field in the signature: it is one of ours
	// (see `smtp::identification`), so it is signed like any other field the
	// server writes. A custom `X-` header from a client still is not.
	let raw = format!(
		"Received: old hop\r\nReturn-Path: <old@example.org>\r\nAuthentication-Results: old\r\nX-Custom: old\r\nReceived-SPF: old\r\n{}",
		message()
	);
	let signature = signer.sign("example.org", raw.as_bytes()).expect("sign");
	for list in signature_headers(signature.as_bytes())
		.iter()
		.map(|field| names(field))
	{
		assert!(!list.iter().any(|name| {
			(name.starts_with("x-") && name != "x-epistle")
				|| [
					"received",
					"return-path",
					"authentication-results",
					"received-spf",
				]
				.contains(&name.as_str())
		}));
	}
	let changed = format!(
		"Received: next hop\r\nX-Other: added\r\n{}",
		raw.replace("old", "new")
	);
	check(&dns, &signature, &changed, DkimOutcome::Pass).await;
}

#[test]
fn signed_header_table_matches_the_signer() {
	let page = include_str!("../../../../docs/headers.md");
	let table = page
		.split("| Signed header | Oversigned |\n|---|---|\n")
		.nth(1)
		.expect("DKIM table");
	let rows: Vec<_> = table
		.lines()
		.take_while(|line| line.starts_with('|'))
		.collect();
	let (signer, _) = fixture(true);
	let raw = format!("Resent-From: sender@example.org\r\n{}", message());
	let signature = signer.sign("example.org", raw.as_bytes()).expect("sign");
	let mut expected = Vec::new();
	let mut documented = Vec::new();
	let mut oversigned = Vec::new();
	for row in rows {
		let cells: Vec<_> = row.split('|').map(str::trim).collect();
		let name = cells[1].trim_matches('`').to_ascii_lowercase();
		if name == "resent-*" {
			assert_eq!(cells[2], "No");
			expected.push("resent-from".to_string());
			continue;
		}
		documented.push(name.clone());
		expected.push(name.clone());
		if cells[2] == "Yes" {
			oversigned.push(name.clone());
			expected.push(name);
		} else {
			assert_eq!(cells[2], "No");
		}
	}
	documented.sort();
	oversigned.sort();
	let mut selected: Vec<_> = SIGNED_HEADERS.to_vec();
	let mut important: Vec<_> = OVERSIGNED_HEADERS.to_vec();
	selected.sort();
	important.sort();
	assert_eq!(documented, selected);
	assert_eq!(oversigned, important);
	expected.sort();
	for mut list in signature_headers(signature.as_bytes())
		.iter()
		.map(|field| names(field))
	{
		list.sort();
		assert_eq!(list, expected);
	}
}
