//! The public endpoint serves the MTA-STS policy next to the client setup
//! documents, from the directory `[mta_sts] policy_dir` names.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tower::ServiceExt;

use crate::config::Config;
use crate::tls::ReloadableAcceptor;
use crate::tls::test_support::acceptor_and_cert;

const PATH: &str = "/.well-known/mta-sts.txt";

fn config(dir: Option<&std::path::Path>) -> Config {
	let section = dir.map_or(String::new(), |dir| {
		format!("[mta_sts]\npolicy_dir = {:?}\nmax_age = 4321\n", dir)
	});
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n\
		 domains = [\"example.org\"]\n{section}"
	))
	.expect("config")
}

async fn call(config: &Config, method: Method) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
	let request = Request::builder()
		.method(method)
		.uri(PATH)
		.body(Body::empty())
		.expect("request");
	let response = super::router_for(config)
		.oneshot(request)
		.await
		.expect("response");
	let (parts, body) = response.into_parts();
	let bytes = axum::body::to_bytes(body, usize::MAX).await.expect("body");
	(parts.status, parts.headers, bytes.to_vec())
}

#[tokio::test]
async fn the_policy_the_server_writes_is_the_one_the_endpoint_serves() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(Some(dir.path()));
	crate::mtasts::publish::write_policy(&config).expect("policy written at start");
	let (status, headers, body) = call(&config, Method::GET).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(headers[header::CONTENT_TYPE], "text/plain; charset=utf-8");
	assert_eq!(headers[header::CACHE_CONTROL], "max-age=4321");
	assert_eq!(
		String::from_utf8(body).expect("utf-8"),
		crate::mtasts::publish::publication(&config).content
	);
}

#[tokio::test]
async fn without_a_policy_directory_the_path_answers_404() {
	let (status, _, _) = call(&config(None), Method::GET).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let router = super::router("mail.example.org".into(), vec!["example.org".into()]);
	let request = Request::get(PATH).body(Body::empty()).expect("request");
	let response = router.oneshot(request).await.expect("response");
	assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn head_has_the_length_and_no_body_and_post_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(Some(dir.path()));
	crate::mtasts::publish::write_policy(&config).expect("policy");
	let (status, headers, body) = call(&config, Method::HEAD).await;
	assert_eq!(status, StatusCode::OK);
	assert!(body.is_empty());
	let length: usize = headers[header::CONTENT_LENGTH]
		.to_str()
		.expect("length")
		.parse()
		.expect("number");
	assert_eq!(
		length,
		crate::mtasts::publish::publication(&config).content.len()
	);
	let (status, headers, _) = call(&config, Method::POST).await;
	assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
	// The router answers a method it does not route before the handler
	// runs, so the header is the router's own.
	let allow = headers[header::ALLOW]
		.to_str()
		.expect("allow")
		.replace(' ', "");
	assert_eq!(allow, "GET,HEAD");
}

#[tokio::test]
async fn a_missing_file_is_404_and_one_that_does_not_parse_is_500() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(Some(dir.path()));
	let (status, _, _) = call(&config, Method::GET).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	std::fs::write(dir.path().join("mta-sts.txt"), "not a policy").expect("file");
	let (status, _, _) = call(&config, Method::GET).await;
	assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn one_tls_listener_answers_the_setup_documents_and_the_policy() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(Some(dir.path()));
	crate::mtasts::publish::write_policy(&config).expect("policy");
	let (acceptor, cert) = acceptor_and_cert();
	let reloadable = ReloadableAcceptor::new(acceptor);
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let addr = listener.local_addr().expect("addr");
	tokio::spawn(super::serve(
		listener,
		super::router_for(&config),
		Some(reloadable.https()),
		8,
		Default::default(),
	));
	let mut roots = RootCertStore::empty();
	roots.add(cert).expect("trust anchor");
	let mut client = ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	client.alpn_protocols = vec![b"http/1.1".to_vec()];
	let connector = TlsConnector::from(Arc::new(client));
	let mut texts = Vec::new();
	for path in ["/mail/config-v1.1.xml?emailaddress=a@example.org", PATH] {
		let tcp = TcpStream::connect(addr).await.expect("connect");
		let name = ServerName::try_from("mail.example.org").expect("name");
		let mut tls = connector.connect(name, tcp).await.expect("handshake");
		let request = format!(
			"GET {path} HTTP/1.1\r\nHost: mta-sts.example.org\r\nConnection: close\r\n\r\n"
		);
		tls.write_all(request.as_bytes()).await.expect("write");
		let mut response = Vec::new();
		let _ = tls.read_to_end(&mut response).await;
		texts.push(String::from_utf8_lossy(&response).into_owned());
	}
	assert!(texts[0].starts_with("HTTP/1.1 200"), "{}", texts[0]);
	assert!(texts[0].contains("<emailProvider"), "{}", texts[0]);
	assert!(texts[1].starts_with("HTTP/1.1 200"), "{}", texts[1]);
	assert!(texts[1].contains("version: STSv1"), "{}", texts[1]);
}
