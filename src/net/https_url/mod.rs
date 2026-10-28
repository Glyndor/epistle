//! An absolute URL that is guaranteed to use the `https` scheme.
//!
//! Every outbound request that carries a credential (a DNS provider token, an
//! OIDC discovery fetch) takes an [`HttpsUrl`] instead of a `String`, so "the
//! credential only travels over TLS" is a property of the type at every call
//! site rather than a check somebody has to remember upstream.
//!
//! Paths are built with [`HttpsUrl::with_segments`], which percent-encodes each
//! segment, so an account or zone identifier containing `/`, `?` or `#` stays
//! one path segment instead of rewriting the request path or smuggling a query.

use std::fmt;

use url::Url;

/// Why a string was refused as an [`HttpsUrl`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpsUrlError {
	/// The text is not an absolute URL.
	Invalid,
	/// The scheme is not `https`.
	NotHttps,
	/// The URL has no host.
	NoHost,
	/// The URL embeds a username or password.
	EmbeddedCredentials,
	/// The URL cannot carry path segments (for example `mailto:`).
	NoPath,
	/// A path segment is `.` or `..` and would rewrite the path.
	DotSegment,
	/// A link a server handed back points at another scheme, host or port.
	OffOrigin,
}

impl fmt::Display for HttpsUrlError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			HttpsUrlError::Invalid => "not an absolute URL",
			HttpsUrlError::NotHttps => "URL must use https://",
			HttpsUrlError::NoHost => "URL has no host",
			HttpsUrlError::EmbeddedCredentials => "URL must not embed credentials",
			HttpsUrlError::NoPath => "URL cannot carry a path",
			HttpsUrlError::DotSegment => "path segment must not be . or ..",
			HttpsUrlError::OffOrigin => "link leaves the origin of the API base",
		})
	}
}

impl std::error::Error for HttpsUrlError {}

/// An absolute `https` URL with a host and no embedded credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsUrl(Url);

impl HttpsUrl {
	/// Parse `text`, refusing every scheme other than `https`.
	pub fn parse(text: &str) -> Result<Self, HttpsUrlError> {
		let url = Url::parse(text).map_err(|_| HttpsUrlError::Invalid)?;
		if url.scheme() != "https" {
			return Err(HttpsUrlError::NotHttps);
		}
		Self::from_checked(url)
	}

	/// An `https` URL from a literal in the source. A literal that is not a
	/// valid `https` URL is a programming error caught the first time the
	/// code runs, so this panics instead of returning a `Result` nobody can
	/// act on.
	pub fn from_static(text: &'static str) -> Self {
		match Self::parse(text) {
			Ok(url) => url,
			Err(err) => panic!("static URL {text:?} is not a usable https URL: {err}"),
		}
	}

	/// A plain-`http` URL for the in-process mock servers the provider tests
	/// start. Only a loopback host is accepted, so even test code cannot point
	/// a credential at a remote cleartext endpoint.
	#[cfg(test)]
	pub(crate) fn loopback_http(text: &str) -> Result<Self, HttpsUrlError> {
		let url = Url::parse(text).map_err(|_| HttpsUrlError::Invalid)?;
		let loopback = match url.host() {
			Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
			Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
			Some(url::Host::Domain(name)) => name == "localhost",
			None => false,
		};
		if url.scheme() != "http" || !loopback {
			return Err(HttpsUrlError::NotHttps);
		}
		Self::from_checked(url)
	}

	fn from_checked(url: Url) -> Result<Self, HttpsUrlError> {
		if url.host().is_none() {
			return Err(HttpsUrlError::NoHost);
		}
		if !url.username().is_empty() || url.password().is_some() {
			return Err(HttpsUrlError::EmbeddedCredentials);
		}
		if url.cannot_be_a_base() {
			return Err(HttpsUrlError::NoPath);
		}
		Ok(HttpsUrl(url))
	}

	/// This URL with `segments` appended to its path. Each segment is
	/// percent-encoded, so `/`, `?` and `#` inside an identifier are data, not
	/// separators. A trailing slash on the base is not doubled, and any query
	/// or fragment on the base is dropped.
	pub fn with_segments<I, S>(&self, segments: I) -> Result<Self, HttpsUrlError>
	where
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		let mut url = self.0.clone();
		url.set_query(None);
		url.set_fragment(None);
		{
			let mut path = url
				.path_segments_mut()
				.map_err(|()| HttpsUrlError::NoPath)?;
			path.pop_if_empty();
			for segment in segments {
				let segment = segment.as_ref();
				if segment == "." || segment == ".." {
					return Err(HttpsUrlError::DotSegment);
				}
				path.push(segment);
			}
		}
		Ok(HttpsUrl(url))
	}

	/// Resolve a link a remote server handed back (a pagination `next`, for
	/// example) against this URL. The link may be absolute or relative, but
	/// the result must have this URL's scheme, host and port: the credential
	/// that travels with the follow-up request must not be steerable to a
	/// host the operator did not configure by anything in a response body.
	pub fn follow(&self, link: &str) -> Result<Self, HttpsUrlError> {
		let target = self.0.join(link).map_err(|_| HttpsUrlError::Invalid)?;
		if target.origin() != self.0.origin() {
			return Err(HttpsUrlError::OffOrigin);
		}
		Self::from_checked(target)
	}

	/// This URL with the query pair `key=value` appended (both percent-encoded).
	pub fn with_query(&self, key: &str, value: &str) -> Self {
		let mut url = self.0.clone();
		url.query_pairs_mut().append_pair(key, value);
		HttpsUrl(url)
	}

	/// The underlying URL by value, for handing to an HTTP client request.
	pub fn into_url(self) -> Url {
		self.0
	}

	/// The URL as text.
	pub fn as_str(&self) -> &str {
		self.0.as_str()
	}

	/// The URL's host, always present.
	pub fn host_str(&self) -> Option<&str> {
		self.0.host_str()
	}

	/// The underlying parsed URL, for handing to an HTTP client.
	pub fn as_url(&self) -> &Url {
		&self.0
	}
}

impl fmt::Display for HttpsUrl {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.0.as_str())
	}
}

#[cfg(test)]
mod tests;
