use super::*;
use tokio::net::TcpListener;

#[tokio::test]
#[ignore = "requires permission to bind TCP listeners"]
async fn unspecified_ipv6_reports_the_published_ipv4_listener() {
	let server = TcpListener::bind("127.0.0.1:0").await.expect("bind IPv4");
	let address = server.local_addr().expect("address");
	let listener: Listener = toml::from_str(&format!(
		"kind = 'smtp'\naddr = '::'\nport = {}\n",
		address.port()
	))
	.expect("listener");
	let reply = tokio::spawn(async move {
		let (mut stream, _) = server.accept().await.expect("accept");
		stream
			.write_all(b"220 mail.example.org ESMTP\r\n")
			.await
			.expect("banner");
	});
	let lines = probe_all(&[listener], None).await.expect("probe");
	reply.abort();
	assert_eq!(
		(
			lines[0].ok,
			lines[0].addr.as_str(),
			lines[0].error.as_deref()
		),
		(true, address.to_string().as_str(), None),
		"an unspecified IPv6 bind must report the answering IPv4 listener"
	);
}

#[tokio::test]
async fn unspecified_ipv6_retries_ipv4_on_connect_refusal_or_timeout() {
	for kind in [
		std::io::ErrorKind::ConnectionRefused,
		std::io::ErrorKind::TimedOut,
	] {
		let listener: Listener =
			toml::from_str("kind = 'smtp'\naddr = '::'\nport = 25").expect("listener");
		let mut dialed = Vec::new();
		let result = connect_listener_with(&listener, |addr| {
			dialed.push(addr);
			std::future::ready(if addr.is_ipv4() {
				Ok(())
			} else {
				Err(std::io::Error::from(kind))
			})
		})
		.await;
		assert_eq!(
			result.ok().map(|(_, addr)| addr.to_string()),
			Some("127.0.0.1:25".to_string()),
			"an unspecified IPv6 bind must report the answering IPv4 listener"
		);
		assert_eq!(
			dialed,
			vec![
				"[::1]:25".parse::<SocketAddr>().unwrap(),
				"127.0.0.1:25".parse().unwrap()
			]
		);
	}
}

#[tokio::test]
async fn specific_binds_and_other_connect_errors_do_not_retry() {
	for (bind, error, expected) in [
		("::1", std::io::ErrorKind::ConnectionRefused, "[::1]:25"),
		("0.0.0.0", std::io::ErrorKind::TimedOut, "127.0.0.1:25"),
		("::", std::io::ErrorKind::PermissionDenied, "[::1]:25"),
	] {
		let listener: Listener =
			toml::from_str(&format!("kind = 'smtp'\naddr = '{bind}'\nport = 25"))
				.expect("listener");
		let mut dialed = Vec::new();
		let result: std::io::Result<((), SocketAddr)> = connect_listener_with(&listener, |addr| {
			dialed.push(addr.to_string());
			std::future::ready(Err(std::io::Error::from(error)))
		})
		.await;
		assert_eq!(result.unwrap_err().kind(), error);
		assert_eq!(
			dialed,
			vec![expected],
			"only the configured loopback may be dialed"
		);
	}
}

#[tokio::test]
async fn answering_ipv6_is_kept_without_an_ipv4_retry() {
	let listener: Listener =
		toml::from_str("kind = 'smtp'\naddr = '::'\nport = 25").expect("listener");
	let mut dialed = Vec::new();
	let (_, address) = connect_listener_with(&listener, |addr| {
		dialed.push(addr.to_string());
		std::future::ready(Ok(()))
	})
	.await
	.expect("connected");
	assert_eq!(address.to_string(), "[::1]:25");
	assert_eq!(dialed, vec!["[::1]:25"]);
}
