//! A listing is up to 1000 pages and each body may be 16 MiB, so a cap per
//! body alone lets a provider fill the memory of the process one page at a
//! time, in the server's DKIM daemon as much as in the CLI. The bodies of one
//! operation share one budget, and an rrset with no record still counts.

use std::sync::atomic::Ordering;

use crate::dns::provider::{DnsProvider, ProviderError, ScopedSecret};
use crate::dns::providers::test_pages::serve_by;
use crate::net::HttpsUrl;

const PAGE_BYTES: usize = 14 * 1024 * 1024;

fn url(base: &str) -> HttpsUrl {
	HttpsUrl::loopback_http(base).expect("loopback url")
}

/// The one body of a 14 MiB page, built once.
fn big(prefix: &str, suffix: &str) -> String {
	format!("{prefix}{}{suffix}", "x".repeat(PAGE_BYTES))
}

#[tokio::test]
async fn forty_pages_of_14_mib_stop_at_the_budget_in_desec() {
	let page = big(
		"[{\"subname\":\"\",\"type\":\"TXT\",\"ttl\":60,\"records\":[\"",
		"\"]}]",
	);
	let (base, hits) = serve_by(move |base, _, _| {
		(
			page.clone(),
			Some(format!(
				"<{base}/domains/example.org/rrsets/?cursor=n>; rel=\"next\""
			)),
		)
	})
	.await;
	let error =
		crate::dns::providers::desec::DesecProvider::new(ScopedSecret::new("example.org", "tok"))
			.with_base(url(&base))
			.list("example.org")
			.await
			.expect_err("an endless listing is an error");
	let ProviderError::Remote(message) = error else {
		panic!("{error:?}");
	};
	assert!(message.contains("larger than"), "{message}");
	assert!(
		hits.load(Ordering::SeqCst) <= 6,
		"the server was asked for {} pages",
		hits.load(Ordering::SeqCst)
	);
}

#[tokio::test]
async fn forty_pages_of_14_mib_stop_at_the_budget_in_digitalocean() {
	let page_of = |base: &str| {
		big(
			"{\"domain_records\":[{\"id\":1,\"type\":\"TXT\",\"name\":\"h\",\"ttl\":60,\"data\":\"",
			&format!(
				"\"}}],\"links\":{{\"pages\":{{\"next\":\"{base}/v2/domains/example.org/records?page=2\"}}}}}}"
			),
		)
	};
	let (base, hits) = serve_by(move |base, _, _| (page_of(base), None)).await;
	let error = crate::dns::providers::digitalocean::DigitaloceanProvider::new(ScopedSecret::new(
		"example.org",
		"tok",
	))
	.with_base(url(&base))
	.list("example.org")
	.await
	.expect_err("an endless listing is an error");
	let ProviderError::Remote(message) = error else {
		panic!("{error:?}");
	};
	assert!(message.contains("larger than"), "{message}");
	assert!(
		hits.load(Ordering::SeqCst) <= 6,
		"the server was asked for {} pages",
		hits.load(Ordering::SeqCst)
	);
}

/// An rrset with `records: []` adds no record, so a count of records alone
/// never stops a page of them: each one counts as one.
#[tokio::test]
async fn rrsets_without_records_count_against_the_record_cap_in_desec() {
	let rrsets = vec!["{\"subname\":\"a\",\"type\":\"A\",\"ttl\":60,\"records\":[]}"; 100_001];
	let body = format!("[{}]", rrsets.join(","));
	let (base, _hits) = serve_by(move |_, _, _| (body.clone(), None)).await;
	let error =
		crate::dns::providers::desec::DesecProvider::new(ScopedSecret::new("example.org", "tok"))
			.with_base(url(&base))
			.list("example.org")
			.await
			.expect_err("too many rrsets");
	assert_eq!(
		error,
		ProviderError::Remote(crate::dns::providers::listing_contract::CAP_MESSAGE.to_string())
	);
}

/// A budget that is spent refuses the next body by name, not as a short read.
/// Four pages of exactly 16 MiB use the 64 MiB up; the fifth finds none left.
#[tokio::test]
async fn a_spent_budget_refuses_the_next_body_by_name() {
	let rrset_head = "[{\"subname\":\"\",\"type\":\"TXT\",\"ttl\":60,\"records\":[\"";
	let rrset_tail = "\"]}]";
	let fill = crate::dns::providers::MAX_BODY - rrset_head.len() - rrset_tail.len();
	let page = format!("{rrset_head}{}{rrset_tail}", "x".repeat(fill));
	assert_eq!(page.len(), crate::dns::providers::MAX_BODY);
	let (base, hits) = serve_by(move |base, _, _| {
		(
			page.clone(),
			Some(format!(
				"<{base}/domains/example.org/rrsets/?cursor=n>; rel=\"next\""
			)),
		)
	})
	.await;
	let error =
		crate::dns::providers::desec::DesecProvider::new(ScopedSecret::new("example.org", "tok"))
			.with_base(url(&base))
			.list("example.org")
			.await
			.expect_err("an endless listing is an error");
	assert_eq!(
		error,
		ProviderError::Remote("the operation read more than its budget".to_string())
	);
	assert_eq!(hits.load(Ordering::SeqCst), 5);
}

/// Cloudflare is the third shape of paging (a page number and a page count).
#[tokio::test]
async fn forty_pages_of_14_mib_stop_at_the_budget_in_cloudflare() {
	let record = big(
		"{\"success\":true,\"result\":[{\"id\":\"1\",\"type\":\"TXT\",\"name\":\"h.example.org\",\"ttl\":60,\"content\":\"",
		"\"}],\"result_info\":{\"total_pages\":1000}}",
	);
	let (base, hits) = serve_by(move |_, path, _| {
		if path.starts_with("/zones?") || path == "/zones" {
			return ("{\"result\":[{\"id\":\"zone123\"}]}".to_string(), None);
		}
		(record.clone(), None)
	})
	.await;
	let error = crate::dns::providers::cloudflare::CloudflareProvider::new(ScopedSecret::new(
		"example.org",
		"tok",
	))
	.with_base(url(&base))
	.list("example.org")
	.await
	.expect_err("an endless listing is an error");
	let ProviderError::Remote(message) = error else {
		panic!("{error:?}");
	};
	assert!(message.contains("larger than"), "{message}");
	assert!(hits.load(Ordering::SeqCst) <= 7);
}

/// Outside an operation there is no budget, and the cap of the single body is
/// what holds: a body past it is refused, not read.
#[tokio::test]
async fn outside_an_operation_the_cap_of_one_body_still_holds() {
	let page = "x".repeat(crate::dns::providers::MAX_BODY + 1);
	let (base, _hits) = serve_by(move |_, _, _| (page.clone(), None)).await;
	let response = reqwest::get(format!("{base}/")).await.expect("get");
	let error = crate::dns::providers::read_body(response)
		.await
		.expect_err("past the cap");
	assert_eq!(
		error,
		ProviderError::Remote(format!(
			"the response is larger than {} bytes",
			crate::dns::providers::MAX_BODY
		))
	);
}
