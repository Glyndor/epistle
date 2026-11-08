//! One webhook endpoint: its HTTP client, URL and signing secret. The
//! server-wide webhook and each tenant's are one of these apiece, built the
//! same way, so a tenant's URL passes the destination policy the
//! server-wide one does.

use std::sync::Arc;
use std::time::Duration;

use super::{WebhookError, destination, sign};

/// Where one receiver is reached and how its requests are signed.
pub(super) struct Endpoint {
	client: reqwest::Client,
	url: String,
	secret: Option<String>,
}

impl Endpoint {
	/// The endpoint a configured section names: the section says whether a
	/// private destination is allowed, and the endpoint follows.
	pub(super) fn from_section(section: &crate::config::Webhook) -> Result<Self, WebhookError> {
		Self::build(
			&section.url,
			section.secret.clone(),
			section.allow_private_webhooks,
		)
	}

	pub(super) fn build(
		url: &str,
		secret: Option<String>,
		allow_private: bool,
	) -> Result<Self, WebhookError> {
		destination::check_url(url, allow_private).map_err(WebhookError::Destination)?;
		let mut builder = reqwest::Client::builder()
			.timeout(Duration::from_secs(15))
			// Never follow a redirect: the POST carries the signature and the
			// event, and a 307 would resend both wherever the endpoint (or
			// whoever took it over) points, an internal address included.
			.redirect(reqwest::redirect::Policy::none())
			// The addresses the host name resolves to are checked as well:
			// a name that points inside the networks of this host is as
			// private as the address it spells.
			.dns_resolver(Arc::new(destination::DestinationResolver { allow_private }));
		if !allow_private {
			// The proxy of the environment resolves the name itself and
			// connects to the address it chooses, so neither the check above
			// nor the resolver would see the address the event reaches. The
			// client that refuses private destinations goes to the endpoint
			// directly; the one that allows them uses the proxy as any
			// other client does.
			builder = builder.no_proxy();
		}
		let client = builder.build()?;
		Ok(Endpoint {
			client,
			url: url.to_string(),
			secret,
		})
	}

	/// The signed POST for a serialized event body.
	pub(super) fn request(&self, body: Vec<u8>) -> reqwest::RequestBuilder {
		let mut request = self
			.client
			.post(&self.url)
			.header(reqwest::header::CONTENT_TYPE, "application/json");
		if let Some(secret) = &self.secret {
			request = request.header("X-Webhook-Signature", sign(secret, &body));
		}
		request.body(body)
	}
}
