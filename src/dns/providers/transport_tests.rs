//! What a provider's network may do to epistle. Every HTTP provider is
//! pointed at a server that misbehaves, with a sentinel where its credential
//! would be:
//!
//! - a port nothing listens on: the error never quotes the request URL.
//!   Some providers carry a credential in it (Namecheap sent its `ApiKey` in
//!   the query of a GET), and the message reaches a terminal, the journal and
//!   support screenshots;
//! - a server that accepts and never answers: the call gives up;
//! - a server that never stops sending: the body is refused past the cap
//!   instead of being held whole in memory.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret};
use crate::dns::providers::{
	MAX_BODY, TEST_OPERATION_DEADLINE, TEST_REQUEST_TIMEOUT, bunny::BunnyProvider,
	cloudflare::CloudflareProvider, desec::DesecProvider, digitalocean::DigitaloceanProvider,
	dnsimple::DnsimpleProvider, godaddy::GodaddyProvider, namecheap::NamecheapProvider,
	ovh::OvhProvider, porkbun::PorkbunProvider, route53::Route53Provider,
	spaceship::SpaceshipProvider,
};
use crate::net::HttpsUrl;

const SENTINEL: &str = "SENTINEL-d41d8cd98f00b204e9800998ecf8427e";

type Named = Vec<(&'static str, Box<dyn DnsProvider>)>;

/// A loopback address whose port was free a moment ago and is closed now.
fn closed() -> String {
	let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
	let port = listener.local_addr().expect("addr").port();
	drop(listener);
	format!("http://127.0.0.1:{port}")
}

/// Every HTTP provider, built to talk to `base`. Build them after setting
/// [`TEST_REQUEST_TIMEOUT`]: the client reads it when it is made.
fn providers(base: &str) -> Named {
	let url = || HttpsUrl::loopback_http(base).expect("loopback url");
	let secret = || ScopedSecret::new("example.org", SENTINEL);
	let namecheap =
		NamecheapProvider::new(ScopedSecret::new("example.org", format!("user:{SENTINEL}")))
			.expect("token")
			.with_client_ip(std::net::Ipv4Addr::new(192, 0, 2, 10))
			.with_api_url(url());
	vec![
		(
			"bunny",
			Box::new(BunnyProvider::new(secret()).with_base(url())),
		),
		(
			"cloudflare",
			Box::new(CloudflareProvider::new(secret()).with_base(url())),
		),
		(
			"desec",
			Box::new(DesecProvider::new(secret()).with_base(url())),
		),
		(
			"digitalocean",
			Box::new(DigitaloceanProvider::new(secret()).with_base(url())),
		),
		(
			"dnsimple",
			Box::new(DnsimpleProvider::new(secret(), "1").with_base(url())),
		),
		(
			"godaddy",
			Box::new(
				GodaddyProvider::new(SENTINEL.into(), SENTINEL.into(), "example.org".into())
					.with_base(url()),
			),
		),
		("namecheap", Box::new(namecheap)),
		(
			"ovh",
			Box::new(OvhProvider::new(SENTINEL.into(), SENTINEL.into(), secret()).with_base(url())),
		),
		(
			"porkbun",
			Box::new(PorkbunProvider::new(secret(), SENTINEL).with_base(url())),
		),
		(
			"route53",
			Box::new(
				Route53Provider::new(SENTINEL.into(), SENTINEL.into(), "Z123".into())
					.with_base(url()),
			),
		),
		(
			"spaceship",
			Box::new(
				SpaceshipProvider::new(SENTINEL.into(), SENTINEL.into(), "example.org".into())
					.with_base(url()),
			),
		),
		(
			"gcloud",
			Box::new(crate::dns::providers::gcloud::test_support::provider_for(
				base,
			)),
		),
	]
}

fn record() -> DnsRecord {
	DnsRecord::new(
		"_dmarc.example.org",
		RecordKind::Txt,
		"v=DMARC1; p=none",
		3600,
	)
}

/// The three operations, each with its error. Route 53 does not list.
async fn outcomes(client: &dyn DnsProvider) -> [(&'static str, Option<ProviderError>); 3] {
	[
		("list", client.list("example.org").await.err()),
		("upsert", client.upsert("example.org", record()).await.err()),
		("delete", client.delete("example.org", record()).await.err()),
	]
}

#[tokio::test]
async fn no_provider_quotes_the_url_in_a_transport_error() {
	for (name, client) in providers(&closed()) {
		for (operation, error) in outcomes(client.as_ref()).await {
			if operation == "list" && error == Some(ProviderError::Unsupported) {
				continue;
			}
			let Some(ProviderError::Remote(message)) = error else {
				panic!("{name} {operation}: not a transport error");
			};
			assert!(
				!message.contains("127.0.0.1"),
				"{name} {operation} quotes the address: {message}"
			);
			assert!(
				!message.contains(SENTINEL),
				"{name} {operation} quotes the credential: {message}"
			);
		}
	}
}

/// Accepts every connection, reads the request head, then `behave`s.
async fn serve<F, Fut>(behave: F) -> String
where
	F: Fn(tokio::net::TcpStream) -> Fut + Send + Sync + 'static,
	Fut: std::future::Future<Output = ()> + Send + 'static,
{
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	let behave = Arc::new(behave);
	tokio::spawn(async move {
		while let Ok((mut stream, _)) = listener.accept().await {
			let behave = behave.clone();
			tokio::spawn(async move {
				let mut head = Vec::new();
				let mut buf = [0u8; 4096];
				while !head.windows(4).any(|w| w == b"\r\n\r\n") {
					match stream.read(&mut buf).await {
						Ok(0) | Err(_) => return,
						Ok(n) => head.extend_from_slice(&buf[..n]),
					}
				}
				behave(stream).await;
			});
		}
	});
	format!("http://{addr}")
}

/// A provider that does not answer cannot hold a command: each call gives up
/// at the request timeout (here 300 ms; 30 s in production), listing,
/// publishing and removing alike.
#[tokio::test]
async fn a_provider_that_never_answers_cannot_hold_a_call() {
	let base = serve(|stream| async move {
		let _held = stream;
		tokio::time::sleep(Duration::from_secs(3600)).await;
	})
	.await;
	TEST_REQUEST_TIMEOUT.with(|t| t.set(Some(Duration::from_millis(300))));
	let named = providers(&base);
	TEST_REQUEST_TIMEOUT.with(|t| t.set(None));
	for (name, client) in named {
		let started = std::time::Instant::now();
		for (operation, error) in outcomes(client.as_ref()).await {
			if operation == "list" && error == Some(ProviderError::Unsupported) {
				continue;
			}
			assert!(
				matches!(error, Some(ProviderError::Remote(_))),
				"{name} {operation}: {error:?}"
			);
		}
		assert!(
			started.elapsed() < Duration::from_secs(20),
			"{name} took {:?}",
			started.elapsed()
		);
	}
}

/// A provider that never stops sending is refused at the cap: the listing
/// fails with the cap in the message, and the server is not read to the end
/// (it would send gigabytes).
#[tokio::test]
async fn a_body_without_an_end_is_refused_at_the_cap() {
	let sent = Arc::new(AtomicUsize::new(0));
	let counter = sent.clone();
	let base = serve(move |mut stream| {
		let counter = counter.clone();
		async move {
			let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
			if stream.write_all(head).await.is_err() {
				return;
			}
			let chunk = [b' '; 64 * 1024];
			for _ in 0..(2 * 1024 * 1024 * 1024 / chunk.len()) {
				let frame = [format!("{:x}\r\n", chunk.len()).as_bytes(), &chunk, b"\r\n"].concat();
				if stream.write_all(&frame).await.is_err() {
					return;
				}
				counter.fetch_add(chunk.len(), Ordering::SeqCst);
			}
		}
	})
	.await;
	for (name, client) in providers(&base) {
		let before = sent.load(Ordering::SeqCst);
		// Route 53 reads a body on the way to a write, not on a list.
		let error = if name == "route53" {
			client.upsert("example.org", record()).await.err()
		} else {
			client.list("example.org").await.err()
		};
		let Some(ProviderError::Remote(message)) = error else {
			panic!("{name}: an endless body was not refused: {error:?}");
		};
		assert!(message.contains("larger than"), "{name}: {message}");
		let read = sent.load(Ordering::SeqCst) - before;
		assert!(
			read < 4 * MAX_BODY,
			"{name} let the server send {read} bytes"
		);
	}
}

/// A provider that answers with a redirect is not followed: the credential
/// a request carries goes to the host epistle was configured with and to no
/// other. The second server must never see a connection.
#[tokio::test]
async fn a_redirect_is_not_followed_to_another_host() {
	let elsewhere = Arc::new(AtomicUsize::new(0));
	let hits = elsewhere.clone();
	let other = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let other_addr = other.local_addr().expect("addr");
	tokio::spawn(async move {
		while let Ok((_stream, _)) = other.accept().await {
			hits.fetch_add(1, Ordering::SeqCst);
		}
	});
	let base = serve(move |mut stream| async move {
		let reply = format!(
			"HTTP/1.1 302 Found\r\nLocation: http://{other_addr}/elsewhere\r\nContent-Length: 0\r\n\r\n"
		);
		let _ = stream.write_all(reply.as_bytes()).await;
	})
	.await;
	for (name, client) in providers(&base) {
		for (operation, error) in outcomes(client.as_ref()).await {
			if operation == "list" && error == Some(ProviderError::Unsupported) {
				continue;
			}
			assert!(
				matches!(error, Some(ProviderError::Remote(_))),
				"{name} {operation}: {error:?}"
			);
		}
	}
	tokio::time::sleep(Duration::from_millis(200)).await;
	assert_eq!(
		elsewhere.load(Ordering::SeqCst),
		0,
		"a provider followed a redirect to another host"
	);
}

/// A provider that sends the body a byte at a time is held no longer than one
/// that sends nothing: the request timeout covers the body too.
#[tokio::test]
async fn a_body_that_drips_cannot_hold_a_call() {
	let base = serve(|mut stream| async move {
		let head =
			b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000000\r\n\r\n";
		if stream.write_all(head).await.is_err() {
			return;
		}
		loop {
			tokio::time::sleep(Duration::from_millis(40)).await;
			if stream.write_all(b" ").await.is_err() {
				return;
			}
		}
	})
	.await;
	TEST_REQUEST_TIMEOUT.with(|t| t.set(Some(Duration::from_millis(300))));
	let named = providers(&base);
	TEST_REQUEST_TIMEOUT.with(|t| t.set(None));
	for (name, client) in named {
		let started = std::time::Instant::now();
		let error = if name == "route53" {
			client.upsert("example.org", record()).await.err()
		} else {
			client.list("example.org").await.err()
		};
		assert!(
			matches!(error, Some(ProviderError::Remote(_))),
			"{name}: {error:?}"
		);
		assert!(
			started.elapsed() < Duration::from_secs(20),
			"{name} took {:?}",
			started.elapsed()
		);
	}
}

/// Each request has its own timeout; the whole operation has a deadline on
/// top, because a listing is up to 1000 requests. With a request timeout
/// that would not fire for half a minute, the deadline ends every operation
/// of every provider.
#[tokio::test]
async fn an_operation_has_a_deadline_of_its_own() {
	let base = serve(|stream| async move {
		let _held = stream;
		tokio::time::sleep(Duration::from_secs(3600)).await;
	})
	.await;
	let named = providers(&base);
	TEST_OPERATION_DEADLINE.with(|t| t.set(Some(Duration::from_millis(300))));
	for (name, client) in named {
		for (operation, error) in outcomes(client.as_ref()).await {
			if operation == "list" && error == Some(ProviderError::Unsupported) {
				continue;
			}
			let Some(ProviderError::Remote(message)) = error else {
				panic!("{name} {operation}: {error:?}");
			};
			assert_eq!(
				message, "the provider did not finish within 300ms",
				"{name} {operation}"
			);
		}
	}
	TEST_OPERATION_DEADLINE.with(|t| t.set(None));
}

/// RFC 2136 is DNS over TCP, not HTTP, and had no bound at all: a server
/// that accepts and says nothing held `dns publish`, the DKIM rotation and
/// the ACME challenge for ever. It gives up at the request timeout, and the
/// operation as a whole at its deadline.
#[tokio::test]
async fn an_rfc2136_server_that_never_answers_cannot_hold_a_call() {
	use crate::dns::providers::rfc2136::Rfc2136Provider;
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(async move {
		let mut held = Vec::new();
		while let Ok((stream, _)) = listener.accept().await {
			held.push(stream);
		}
	});
	let provider = Rfc2136Provider::new(
		ScopedSecret::new("example.org", "c2VjcmV0"),
		"key.",
		None,
		&addr.to_string(),
	)
	.expect("provider");
	TEST_REQUEST_TIMEOUT.with(|t| t.set(Some(Duration::from_millis(300))));
	let started = std::time::Instant::now();
	for (operation, error) in [
		("upsert", provider.upsert("example.org", record()).await),
		("delete", provider.delete("example.org", record()).await),
	]
	.map(|(op, result)| (op, result.err()))
	{
		assert_eq!(
			error,
			Some(ProviderError::Remote(format!(
				"{addr} did not answer in time"
			))),
			"{operation}"
		);
	}
	TEST_REQUEST_TIMEOUT.with(|t| t.set(None));
	assert!(started.elapsed() < Duration::from_secs(20));
	TEST_OPERATION_DEADLINE.with(|t| t.set(Some(Duration::from_millis(300))));
	let error = provider.upsert("example.org", record()).await.err();
	TEST_OPERATION_DEADLINE.with(|t| t.set(None));
	assert_eq!(
		error,
		Some(ProviderError::Remote(
			"the provider did not finish within 300ms".to_string()
		))
	);
}
