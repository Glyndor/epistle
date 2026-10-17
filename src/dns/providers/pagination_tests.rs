//! A listing whose pages do not add up to what it says about itself is an
//! error, never a zone with records missing: a delegation on the page that
//! did not come would be written over. Each provider that gives a total is
//! fed pages that contradict it (an empty page before the total, a total
//! below what was read, a total that moves, more pages than the total
//! allows) and one that agrees.

use crate::dns::provider::{DnsProvider, ProviderError, ScopedSecret};
use crate::dns::providers::test_pages::serve_by;
use crate::net::HttpsUrl;

const INCONSISTENT: &str =
	"the example.org listing is inconsistent: its pages do not add up to the total it gives";

fn url(base: &str) -> HttpsUrl {
	HttpsUrl::loopback_http(base).expect("loopback url")
}

fn secret() -> ScopedSecret {
	ScopedSecret::new("example.org", "tok")
}

/// The `page=N` of a query, 1 when there is none.
fn page_of(path: &str) -> usize {
	path.split(['?', '&'])
		.find_map(|p| p.strip_prefix("page=")?.parse().ok())
		.unwrap_or(1)
}

async fn assert_inconsistent(label: &str, result: Result<usize, ProviderError>) {
	assert_eq!(
		result,
		Err(ProviderError::Remote(INCONSISTENT.to_string())),
		"{label}"
	);
}

// Spaceship: `{"items": [...], "total": T}`, asked page after page.

fn space_items(from: usize, n: usize) -> String {
	(from..from + n)
		.map(|i| {
			format!("{{\"type\":\"A\",\"name\":\"h{i}\",\"address\":\"192.0.2.1\",\"ttl\":60}}")
		})
		.collect::<Vec<_>>()
		.join(",")
}

fn space_page(from: usize, n: usize, total: i64) -> String {
	format!("{{\"items\":[{}],\"total\":{total}}}", space_items(from, n))
}

async fn spaceship(pages: Vec<String>) -> Result<usize, ProviderError> {
	let (base, _hits) =
		serve_by(move |_, _, n| (pages[n.min(pages.len() - 1)].clone(), None)).await;
	crate::dns::providers::spaceship::SpaceshipProvider::new(
		"k".into(),
		"s".into(),
		"example.org".into(),
	)
	.with_base(url(&base))
	.list("example.org")
	.await
	.map(|records| records.len())
}

#[tokio::test]
async fn spaceship_pages_that_do_not_add_up_are_an_error() {
	let empty = |total: i64| format!("{{\"items\":[],\"total\":{total}}}");
	assert_inconsistent("an empty first page", spaceship(vec![empty(1000)]).await).await;
	assert_inconsistent(
		"a total of zero over a full page",
		spaceship(vec![space_page(0, 500, 0)]).await,
	)
	.await;
	assert_inconsistent(
		"the second page empty before the total",
		spaceship(vec![space_page(0, 500, 900), empty(900)]).await,
	)
	.await;
	assert_inconsistent(
		"a negative total",
		spaceship(vec![space_page(0, 500, -1)]).await,
	)
	.await;
	assert_inconsistent(
		"a total that moves",
		spaceship(vec![space_page(0, 500, 900), space_page(500, 400, 1000)]).await,
	)
	.await;
	assert_inconsistent(
		"more than the total",
		spaceship(vec![space_page(0, 500, 600), space_page(500, 500, 600)]).await,
	)
	.await;
	assert_eq!(
		spaceship(vec![space_page(0, 500, 600), space_page(500, 100, 600)]).await,
		Ok(600)
	);
	assert_eq!(spaceship(vec![space_page(0, 3, 3)]).await, Ok(3));
	assert_eq!(spaceship(vec![empty(0)]).await, Ok(0));
}

// Cloudflare: `result_info.total_pages` and `total_count`, `?page=N`.

fn cf_records(from: usize, n: usize) -> String {
	(from..from + n)
		.map(|i| {
			format!(
				"{{\"id\":\"{i}\",\"type\":\"A\",\"name\":\"h{i}.example.org\",\"content\":\"192.0.2.1\",\"ttl\":60}}"
			)
		})
		.collect::<Vec<_>>()
		.join(",")
}

fn cf_page(from: usize, n: usize, pages: u32, count: usize) -> String {
	format!(
		"{{\"success\":true,\"result\":[{}],\"result_info\":{{\"total_pages\":{pages},\"total_count\":{count}}}}}",
		cf_records(from, n)
	)
}

async fn cloudflare(pages: Vec<String>) -> Result<usize, ProviderError> {
	let (base, _hits) = serve_by(move |_, path, _| {
		if path.starts_with("/zones?") || path == "/zones" {
			return ("{\"result\":[{\"id\":\"zone123\"}]}".to_string(), None);
		}
		(
			pages[(page_of(path) - 1).min(pages.len() - 1)].clone(),
			None,
		)
	})
	.await;
	crate::dns::providers::cloudflare::CloudflareProvider::new(secret())
		.with_base(url(&base))
		.list("example.org")
		.await
		.map(|records| records.len())
}

#[tokio::test]
async fn cloudflare_pages_that_do_not_add_up_are_an_error() {
	assert_inconsistent(
		"the second page empty before the last",
		cloudflare(vec![cf_page(0, 100, 2, 150), cf_page(100, 0, 2, 150)]).await,
	)
	.await;
	assert_inconsistent(
		"fewer records than the count at the last page",
		cloudflare(vec![cf_page(0, 100, 2, 150), cf_page(100, 40, 2, 150)]).await,
	)
	.await;
	assert_inconsistent(
		"more records than the count",
		cloudflare(vec![cf_page(0, 100, 1, 50)]).await,
	)
	.await;
	assert_inconsistent(
		"more records than the count, with pages still to come",
		cloudflare(vec![cf_page(0, 100, 2000, 50)]).await,
	)
	.await;
	assert_inconsistent(
		"a middle page empty",
		cloudflare(vec![
			cf_page(0, 100, 3, 250),
			cf_page(100, 0, 3, 250),
			cf_page(100, 150, 3, 250),
		])
		.await,
	)
	.await;
	assert_inconsistent(
		"a page count that moves",
		cloudflare(vec![cf_page(0, 100, 2, 150), cf_page(100, 50, 3, 150)]).await,
	)
	.await;
	assert_eq!(
		cloudflare(vec![cf_page(0, 100, 2, 150), cf_page(100, 50, 2, 150)]).await,
		Ok(150)
	);
}

// DNSimple: `pagination.total_pages` and `total_entries`, `?page=N`.

fn ds_records(from: usize, n: usize) -> String {
	(from..from + n)
		.map(|i| {
			format!(
				"{{\"id\":{i},\"name\":\"h{i}\",\"type\":\"A\",\"content\":\"192.0.2.1\",\"ttl\":60,\"priority\":null}}"
			)
		})
		.collect::<Vec<_>>()
		.join(",")
}

fn ds_page(from: usize, n: usize, pages: u32, entries: usize) -> String {
	format!(
		"{{\"data\":[{}],\"pagination\":{{\"total_pages\":{pages},\"total_entries\":{entries}}}}}",
		ds_records(from, n)
	)
}

async fn dnsimple(pages: Vec<String>) -> Result<usize, ProviderError> {
	let (base, _hits) = serve_by(move |_, path, _| {
		(
			pages[(page_of(path) - 1).min(pages.len() - 1)].clone(),
			None,
		)
	})
	.await;
	crate::dns::providers::dnsimple::DnsimpleProvider::new(secret(), "1")
		.with_base(url(&format!("{base}/v2")))
		.list("example.org")
		.await
		.map(|records| records.len())
}

#[tokio::test]
async fn dnsimple_pages_that_do_not_add_up_are_an_error() {
	assert_inconsistent(
		"the second page empty before the last",
		dnsimple(vec![ds_page(0, 100, 2, 150), ds_page(100, 0, 2, 150)]).await,
	)
	.await;
	assert_inconsistent(
		"fewer records than the entries at the last page",
		dnsimple(vec![ds_page(0, 100, 2, 150), ds_page(100, 40, 2, 150)]).await,
	)
	.await;
	assert_inconsistent(
		"more records than the entries",
		dnsimple(vec![ds_page(0, 100, 1, 50)]).await,
	)
	.await;
	assert_inconsistent(
		"more records than the entries, with pages still to come",
		dnsimple(vec![ds_page(0, 100, 2000, 50)]).await,
	)
	.await;
	assert_inconsistent(
		"a middle page empty",
		dnsimple(vec![
			ds_page(0, 100, 3, 250),
			ds_page(100, 0, 3, 250),
			ds_page(100, 150, 3, 250),
		])
		.await,
	)
	.await;
	assert_inconsistent(
		"a page count that moves",
		dnsimple(vec![ds_page(0, 100, 2, 150), ds_page(100, 50, 3, 150)]).await,
	)
	.await;
	assert_eq!(
		dnsimple(vec![ds_page(0, 100, 2, 150), ds_page(100, 50, 2, 150)]).await,
		Ok(150)
	);
}

// DigitalOcean: `meta.total` and `links.pages.next`.

fn do_page(base: &str, from: usize, n: usize, next: bool, total: usize) -> String {
	let records = (from..from + n)
		.map(|i| {
			format!(
				"{{\"id\":{i},\"type\":\"A\",\"name\":\"h{i}\",\"data\":\"192.0.2.1\",\"ttl\":60}}"
			)
		})
		.collect::<Vec<_>>()
		.join(",");
	let next = if next {
		format!("\"{base}/v2/domains/example.org/records?page=2\"")
	} else {
		"null".to_string()
	};
	format!(
		"{{\"domain_records\":[{records}],\"links\":{{\"pages\":{{\"next\":{next}}}}},\"meta\":{{\"total\":{total}}}}}"
	)
}

async fn digitalocean(
	pages: impl Fn(&str, usize) -> String + Send + Sync + 'static,
) -> Result<usize, ProviderError> {
	let (base, _hits) = serve_by(move |base, path, _| (pages(base, page_of(path)), None)).await;
	crate::dns::providers::digitalocean::DigitaloceanProvider::new(secret())
		.with_base(url(&base))
		.list("example.org")
		.await
		.map(|records| records.len())
}

#[tokio::test]
async fn digitalocean_pages_that_do_not_add_up_are_an_error() {
	assert_inconsistent(
		"the last page empty before the total",
		digitalocean(|base, page| match page {
			1 => do_page(base, 0, 100, true, 150),
			_ => do_page(base, 100, 0, false, 150),
		})
		.await,
	)
	.await;
	assert_inconsistent(
		"more than the total",
		digitalocean(|base, _| do_page(base, 0, 100, false, 50)).await,
	)
	.await;
	assert_inconsistent(
		"more than the total, with pages still to come",
		digitalocean(|base, _| do_page(base, 0, 100, true, 50)).await,
	)
	.await;
	assert_inconsistent(
		"a next page after the total was reached",
		digitalocean(|base, _| do_page(base, 0, 100, true, 100)).await,
	)
	.await;
	assert_eq!(
		digitalocean(|base, page| match page {
			1 => do_page(base, 0, 100, true, 150),
			_ => do_page(base, 100, 50, false, 150),
		})
		.await,
		Ok(150)
	);
}

// deSEC: the `Link` header. A next page nobody can read is not the end.

async fn desec_link(link: &str) -> Result<usize, ProviderError> {
	let link = link.to_string();
	let (base, _hits) = serve_by(move |base, _, _| {
		(
			"[{\"subname\":\"\",\"type\":\"A\",\"ttl\":60,\"records\":[\"192.0.2.1\"]}]"
				.to_string(),
			Some(link.replace("{base}", base)),
		)
	})
	.await;
	crate::dns::providers::desec::DesecProvider::new(secret())
		.with_base(url(&base))
		.list("example.org")
		.await
		.map(|records| records.len())
}

#[tokio::test]
async fn a_desec_link_that_names_a_next_page_nobody_can_read_is_an_error() {
	for link in [
		"{base}/rrsets/?cursor=a; rel=\"next\"",
		"<{base}/rrsets/?cursor=a; rel=\"next\"",
		"<{base}/rrsets/?cursor=a>; rel=\"next",
		"<>; rel=\"next\"",
	] {
		let result = desec_link(link).await;
		assert!(
			matches!(&result, Err(ProviderError::Remote(_))),
			"{link}: {result:?}"
		);
	}
	// A comma inside the URL, and several relations in one `rel`, are read.
	for link in [
		"<{base}/domains/example.org/rrsets/?cursor=a,b>; rel=\"next\"",
		"<{base}/domains/example.org/rrsets/?cursor=a>; rel=\"prev next\"",
	] {
		let result = desec_link(link).await;
		assert_ne!(result, Ok(1), "{link}: the next page was not followed");
	}
}

/// A `Link` that names another origin (another port, another host name,
/// another scheme) is refused: the token that travels with the follow-up
/// request goes to the host that was configured and to no other.
#[tokio::test]
async fn a_desec_link_to_another_origin_is_never_followed() {
	let (other, other_hits) = serve_by(|_, _, _| ("[]".to_string(), None)).await;
	for (label, link) in [
		(
			"another port",
			format!("<{other}/domains/example.org/rrsets/?cursor=n>; rel=\"next\""),
		),
		(
			"another host name",
			"<http://localhost:{port}/domains/example.org/rrsets/?cursor=n>; rel=\"next\""
				.to_string(),
		),
		(
			"another scheme",
			"<https://127.0.0.1:{port}/domains/example.org/rrsets/?cursor=n>; rel=\"next\""
				.to_string(),
		),
		(
			"a bare host",
			"<//elsewhere.example/domains/example.org/rrsets/?cursor=n>; rel=\"next\"".to_string(),
		),
	] {
		let own_link = link.clone();
		let (base, hits) = serve_by(move |base, _, _| {
			let port = base.rsplit(':').next().expect("port");
			(
				"[{\"subname\":\"\",\"type\":\"A\",\"ttl\":60,\"records\":[\"192.0.2.1\"]}]"
					.to_string(),
				Some(own_link.replace("{port}", port)),
			)
		})
		.await;
		let result = crate::dns::providers::desec::DesecProvider::new(secret())
			.with_base(url(&base))
			.list("example.org")
			.await;
		assert!(
			matches!(&result, Err(ProviderError::Remote(m)) if m.contains("invalid request URL")),
			"{label}: {result:?}"
		);
		assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1, "{label}");
	}
	assert_eq!(other_hits.load(std::sync::atomic::Ordering::SeqCst), 0);
}
