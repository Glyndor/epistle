//! F07: observe the HTTPS destination after the address screen, with valid TLS.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_rustls::{TlsAcceptor, rustls};

use super::*;

struct Server {
	addr: SocketAddr,
	tcp: Arc<AtomicUsize>,
	http: Arc<AtomicUsize>,
	task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
	fn drop(&mut self) {
		self.task.abort();
	}
}

async fn serve(acceptor: TlsAcceptor, body: String) -> Server {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let tcp = Arc::new(AtomicUsize::new(0));
	let http = Arc::new(AtomicUsize::new(0));
	let (connections, requests) = (tcp.clone(), http.clone());
	let task = tokio::spawn(async move {
		while let Ok((stream, _)) = listener.accept().await {
			connections.fetch_add(1, Ordering::SeqCst);
			let (acceptor, body, requests) = (acceptor.clone(), body.clone(), requests.clone());
			tokio::spawn(async move {
				let stream = acceptor
					.accept(stream)
					.await
					.expect("hostname-valid TLS handshake");
				let mut stream = BufReader::new(stream);
				let mut line = String::new();
				loop {
					line.clear();
					assert!(stream.read_line(&mut line).await.unwrap() > 0);
					if line == "\r\n" {
						break;
					}
				}
				requests.fetch_add(1, Ordering::SeqCst);
				let response = format!(
					"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
					body.len()
				);
				stream.write_all(response.as_bytes()).await.unwrap();
				stream.shutdown().await.unwrap();
			});
		}
	});
	Server {
		addr,
		tcp,
		http,
		task,
	}
}

/// The screen sees a public address; the HTTP client's subsequent resolution
/// sees the internal sentinel. Both stages record their order, so a test that
/// never reached the screen cannot masquerade as a rebinding attempt.
struct Rebinding {
	idp: SocketAddr,
	sentinel: SocketAddr,
	screen_ip: IpAddr,
	events: Arc<Mutex<Vec<String>>>,
}

impl NameResolver for Rebinding {
	fn lookup(&self, name: &str) -> Result<Vec<IpAddr>, OidcError> {
		self.events.lock().unwrap().push(format!("screen:{name}"));
		Ok(vec![if name == "jwks.idp.example" {
			self.screen_ip
		} else {
			"8.8.8.8".parse().unwrap()
		}])
	}
}

impl Resolve for Rebinding {
	fn resolve(&self, name: Name) -> Resolving {
		self.events
			.lock()
			.unwrap()
			.push(format!("transport:{}", name.as_str()));
		let address = match name.as_str() {
			"idp.example" => self.idp,
			"jwks.idp.example" => self.sentinel,
			other => panic!("unexpected transport DNS query {other}"),
		};
		Box::pin(async move { Ok(Box::new(std::iter::once(address)) as Addrs) })
	}
}

fn client(
	resolver: Arc<Rebinding>,
	cert: &rustls::pki_types::CertificateDer<'static>,
) -> impl Fn() -> reqwest::ClientBuilder {
	let cert = cert.clone();
	move || {
		reqwest::Client::builder()
			.no_proxy()
			.redirect(reqwest::redirect::Policy::none())
			.timeout(Duration::from_secs(3))
			.tls_certs_only([reqwest::Certificate::from_der(&cert).unwrap()])
			.dns_resolver(resolver.clone())
	}
}

#[tokio::test]
async fn hostile_f07_public_screen_cannot_rebind_https_to_loopback() {
	crate::tls::ensure_crypto_provider();
	// The test root is explicitly trusted, and both names are in its SANs.
	// Neither certificate rejection nor a hostname mismatch can hide a dial.
	let certified =
		rcgen::generate_simple_self_signed(vec!["idp.example".into(), "jwks.idp.example".into()])
			.unwrap();
	let cert = certified.cert.der().clone();
	let key =
		rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
	let config = rustls::ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(vec![cert.clone()], key)
		.unwrap();
	let acceptor = TlsAcceptor::from(Arc::new(config));
	let jwks = r#"{"keys":[{"kty":"RSA","kid":"sentinel","n":"gA","e":"AQAB"}]}"#.to_string();
	let expected = parse_jwks(&jwks, Algorithm::Rs256).unwrap();
	let sentinel = serve(acceptor.clone(), jwks).await;
	let jwks_url = format!("https://jwks.idp.example:{}/jwks", sentinel.addr.port());
	let idp = serve(
		acceptor,
		serde_json::json!({"jwks_uri": jwks_url}).to_string(),
	)
	.await;
	let discovery = parse_endpoint(&format!(
		"https://idp.example:{}/discovery",
		idp.addr.port()
	))
	.unwrap();
	let events = Arc::new(Mutex::new(Vec::new()));
	let make_resolver = |screen_ip| {
		Arc::new(Rebinding {
			idp: idp.addr,
			sentinel: sentinel.addr,
			screen_ip,
			events: events.clone(),
		})
	};

	// Positive transport control: a permitted internal deployment really can
	// fetch and parse the sentinel's keys using this CA, name and client.
	let private = make_resolver("127.0.0.1".parse().unwrap());
	let private_client = client(private.clone(), &cert);
	assert_eq!(
		fetch_keys(
			&private_client,
			&discovery,
			Algorithm::Rs256,
			true,
			&*private
		)
		.await,
		Ok(expected)
	);
	assert_eq!(sentinel.http.load(Ordering::SeqCst), 1);
	let before = sentinel.tcp.load(Ordering::SeqCst);
	let blocked = fetch_keys(
		&private_client,
		&discovery,
		Algorithm::Rs256,
		false,
		&*private,
	)
	.await;
	assert!(
		matches!(blocked, Err(OidcError::JwksUriOffScope(_))),
		"visible private address must be rejected: {blocked:?}"
	);
	assert_eq!(
		sentinel.tcp.load(Ordering::SeqCst),
		before,
		"visible private address reached sentinel"
	);

	events.lock().unwrap().clear();
	let rebinding = make_resolver("8.8.8.8".parse().unwrap());
	let result = fetch_keys(
		&client(rebinding.clone(), &cert),
		&discovery,
		Algorithm::Rs256,
		false,
		&*rebinding,
	)
	.await;
	let seen = events.lock().unwrap().clone();
	assert!(
		seen.iter().any(|e| e == "screen:jwks.idp.example"),
		"missing screening lookup: {seen:?}"
	);
	if let Some(transport) = seen.iter().position(|e| e == "transport:jwks.idp.example") {
		assert!(
			seen.iter()
				.position(|e| e == "screen:jwks.idp.example")
				.unwrap() < transport,
			"transport preceded screen: {seen:?}"
		);
	}
	assert_eq!(
		sentinel.tcp.load(Ordering::SeqCst),
		before,
		"JWKS DNS rebinding reached internal TCP sentinel; HTTP requests={}, fetch={result:?}, events={seen:?}",
		sentinel.http.load(Ordering::SeqCst)
	);
	assert!(result.is_err(), "rebinding must fail safely: {result:?}");
}
