//! The URL rule for webhook endpoints, checked on the parsed host.

/// Event payloads carry message metadata, so the endpoint must use TLS unless
/// it is a loopback address that never leaves the host. The check looks at the
/// parsed host, so a name like `localhost.example.net` is not loopback.
pub(super) fn check(raw: &str) -> Result<(), String> {
	let url = reqwest::Url::parse(raw).map_err(|_| format!("\"{raw}\" is not a valid URL"))?;
	if !url.username().is_empty() || url.password().is_some() {
		return Err(
			"the URL must not contain credentials: sign requests with --secret-stdin instead"
				.into(),
		);
	}
	let loopback = match url.host() {
		Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
		Some(url::Host::Ipv4(address)) => address.is_loopback(),
		Some(url::Host::Ipv6(address)) => address.is_loopback(),
		None => return Err(format!("\"{raw}\" has no host")),
	};
	match url.scheme() {
		"https" => Ok(()),
		"http" if loopback => Ok(()),
		_ => Err("the URL must be https (or a loopback http endpoint)".into()),
	}
}
