//! One module per DNS provider epistle can publish records through. Each
//! provider lives in its own directory with its tests; what they share (the
//! `DnsProvider` trait, record types, matching rules) is in
//! [`crate::dns::provider`].

/// The most pages a provider listing reads. A server that keeps handing out
/// pages (or claims a million of them) cannot keep a listing going for ever,
/// and a listing that stops at the cap is an error, not a shorter zone: a
/// delegation that fell off the end would be written over.
pub(crate) const LIST_MAX_PAGES: usize = 1000;

/// The most records a provider listing returns, for the same reason.
pub(crate) const LIST_MAX_RECORDS: usize = 100_000;

/// The error a listing returns when it hits [`LIST_MAX_PAGES`] or
/// [`LIST_MAX_RECORDS`].
pub(crate) fn listing_too_long(zone: &str) -> crate::dns::provider::ProviderError {
	crate::dns::provider::ProviderError::Remote(format!(
		"the {zone} zone is larger than a listing reads ({LIST_MAX_PAGES} pages, {LIST_MAX_RECORDS} records)"
	))
}

/// How long a provider may take to accept a connection.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long one request may take, connection and body included. Every call
/// to a provider is a request, so this is the bound on a listing, a publish
/// and an undo alike.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The most bytes one response body may have. A zone of 100000 records is
/// about 16 MiB of JSON; a provider that answers more is refused, and the
/// body is never held whole in memory. Namecheap, whose answer is a whole
/// zone of XML, keeps its own 256 KiB.
pub(crate) const MAX_BODY: usize = 16 * 1024 * 1024;

#[cfg(test)]
thread_local! {
	/// Tests that need a request to give up in milliseconds set this before
	/// they build their providers; it is read when the client is built.
	pub(crate) static TEST_REQUEST_TIMEOUT: std::cell::Cell<Option<std::time::Duration>> =
		const { std::cell::Cell::new(None) };
}

/// How long one whole operation may take: a listing across all its pages, a
/// publish with the reads it makes first, an undo step. The request timeout
/// bounds each call; this bounds the sum, so 1000 pages of 30 seconds are not
/// a day.
const OPERATION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

#[cfg(test)]
thread_local! {
	/// Like [`TEST_REQUEST_TIMEOUT`], for the deadline of a whole operation;
	/// read when the operation starts.
	pub(crate) static TEST_OPERATION_DEADLINE: std::cell::Cell<Option<std::time::Duration>> =
		const { std::cell::Cell::new(None) };
}

/// The most bytes all the response bodies of one operation may add up to. A
/// listing is up to 1000 pages and each page may be [`MAX_BODY`], so the cap
/// per body alone lets a provider (or a zone) fill the memory of the process
/// one page at a time, in the server's DKIM daemon as much as in the CLI.
const MAX_OPERATION_BYTES: usize = 64 * 1024 * 1024;

tokio::task_local! {
	/// What is left of [`MAX_OPERATION_BYTES`] for the operation running on
	/// this task; [`read_bounded`] takes from it.
	static BYTES_LEFT: std::cell::Cell<usize>;
}

/// How long to wait for a connection: [`CONNECT_TIMEOUT`], or less when a
/// test asks for it.
pub(crate) fn connect_timeout() -> std::time::Duration {
	request_timeout().min(CONNECT_TIMEOUT)
}

/// How long one request may take: [`REQUEST_TIMEOUT`], or what a test set.
/// The HTTP client and the RFC 2136 exchange both use it.
pub(crate) fn request_timeout() -> std::time::Duration {
	#[cfg(test)]
	return TEST_REQUEST_TIMEOUT
		.with(|t| t.get())
		.unwrap_or(REQUEST_TIMEOUT);
	#[cfg(not(test))]
	REQUEST_TIMEOUT
}

/// Run one provider operation under [`OPERATION_DEADLINE`] and a budget of
/// [`MAX_OPERATION_BYTES`] for everything it reads. Every `list`, `upsert` and
/// `delete` of the providers goes through it.
pub(crate) async fn within<T>(
	operation: impl std::future::Future<Output = Result<T, crate::dns::provider::ProviderError>>,
) -> Result<T, crate::dns::provider::ProviderError> {
	#[cfg(test)]
	let limit = TEST_OPERATION_DEADLINE
		.with(|t| t.get())
		.unwrap_or(OPERATION_DEADLINE);
	#[cfg(not(test))]
	let limit = OPERATION_DEADLINE;
	tokio::time::timeout(
		limit,
		BYTES_LEFT.scope(std::cell::Cell::new(MAX_OPERATION_BYTES), operation),
	)
	.await
	.unwrap_or_else(|_| {
		Err(crate::dns::provider::ProviderError::Remote(format!(
			"the provider did not finish within {limit:?}"
		)))
	})
}

/// The error for a full page that does not say whether more follow.
pub(crate) fn missing_page_count(zone: &str) -> crate::dns::provider::ProviderError {
	crate::dns::provider::ProviderError::Remote(format!(
		"the {zone} listing does not say how many pages there are"
	))
}

/// The error for pages that do not add up: a page empty before the total,
/// a total smaller than what was read, a total that changes from page to
/// page, more pages than the total allows. A listing whose pages disagree
/// with what it says about itself is never returned as the zone.
pub(crate) fn inconsistent_pages(zone: &str) -> crate::dns::provider::ProviderError {
	crate::dns::provider::ProviderError::Remote(format!(
		"the {zone} listing is inconsistent: its pages do not add up to the total it gives"
	))
}

/// [`within`] for a listing: the same deadline, and a zone of more than
/// [`LIST_MAX_RECORDS`] records is an error, whatever the provider's paging
/// did, not a zone cut short.
pub(crate) async fn listing(
	zone: String,
	operation: impl std::future::Future<
		Output = Result<Vec<crate::dns::provider::DnsRecord>, crate::dns::provider::ProviderError>,
	>,
) -> Result<Vec<crate::dns::provider::DnsRecord>, crate::dns::provider::ProviderError> {
	let records = within(operation).await?;
	if records.len() > LIST_MAX_RECORDS {
		return Err(listing_too_long(&zone));
	}
	Ok(records)
}

/// The HTTP client every provider uses: a connect timeout, a total timeout,
/// and no redirects, so a provider (or whoever sits in front of it) cannot
/// send the credential to another host or keep a command waiting.
pub(crate) fn http_client() -> reqwest::Client {
	reqwest::Client::builder()
		.connect_timeout(connect_timeout())
		.timeout(request_timeout())
		.redirect(reqwest::redirect::Policy::none())
		.build()
		.expect("an HTTP client with a timeout builds like the default one")
}

/// A transport failure as a provider error. The request URL is left out of the
/// message: some providers carry a credential in it (Namecheap's `ApiKey`), and
/// the message reaches a terminal, a log and a support screenshot.
pub(crate) fn transport(error: reqwest::Error) -> crate::dns::provider::ProviderError {
	crate::dns::provider::ProviderError::Remote(error.without_url().to_string())
}

/// The body of `response` as text, read chunk by chunk and refused past
/// [`MAX_BODY`].
pub(crate) async fn read_body(
	response: reqwest::Response,
) -> Result<String, crate::dns::provider::ProviderError> {
	read_bounded(response, MAX_BODY).await
}

/// The body of `response` as text, refused as soon as it is past `limit`
/// bytes: the announced length is checked first, and a body that does not
/// announce one is counted as it arrives.
pub(crate) async fn read_bounded(
	mut response: reqwest::Response,
	limit: usize,
) -> Result<String, crate::dns::provider::ProviderError> {
	// Inside an operation the body also draws on what is left of its budget,
	// and a budget that is spent refuses the next body outright. Outside one
	// (no operation, so no budget) the cap of the single body is all there
	// is, never "no cap".
	let left = BYTES_LEFT.try_with(|left| left.get()).ok();
	if left == Some(0) {
		return Err(crate::dns::provider::ProviderError::Remote(
			"the operation read more than its budget".to_string(),
		));
	}
	let limit = left.map_or(limit, |left| limit.min(left));
	let too_large = || {
		crate::dns::provider::ProviderError::Remote(format!(
			"the response is larger than {limit} bytes"
		))
	};
	if response.content_length().is_some_and(|n| n > limit as u64) {
		return Err(too_large());
	}
	let mut body = Vec::new();
	while let Some(chunk) = response.chunk().await.map_err(transport)? {
		if body.len() + chunk.len() > limit {
			return Err(too_large());
		}
		body.extend_from_slice(&chunk);
	}
	let _ = BYTES_LEFT.try_with(|left| left.set(left.get().saturating_sub(body.len())));
	Ok(String::from_utf8_lossy(&body).into_owned())
}

pub mod bunny;
pub mod check;
pub mod cloudflare;
pub mod desec;
pub mod digitalocean;
pub mod dnsimple;
pub mod gcloud;
pub mod godaddy;
pub mod namecheap;
pub mod ovh;
pub mod porkbun;
pub mod rfc2136;
pub mod route53;
pub mod spaceship;

#[cfg(test)]
pub(crate) mod tests;
