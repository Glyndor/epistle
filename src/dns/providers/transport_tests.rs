//! A transport failure never quotes the request URL. Some providers carry a
//! credential in it (Namecheap sent its `ApiKey` in the query of a GET), and
//! the message reaches a terminal, the journal and support screenshots. Every
//! HTTP provider is pointed at a port nothing listens on, with a sentinel
//! where its credential would be, and each operation must fail without
//! either the address or the sentinel in the error.

use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret};
use crate::dns::providers::{
	bunny::BunnyProvider, cloudflare::CloudflareProvider, desec::DesecProvider,
	digitalocean::DigitaloceanProvider, dnsimple::DnsimpleProvider, godaddy::GodaddyProvider,
	namecheap::NamecheapProvider, ovh::OvhProvider, porkbun::PorkbunProvider,
	route53::Route53Provider, spaceship::SpaceshipProvider,
};
use crate::net::HttpsUrl;

const SENTINEL: &str = "SENTINEL-d41d8cd98f00b204e9800998ecf8427e";

/// A loopback address whose port was free a moment ago and is closed now.
fn closed() -> String {
	let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
	let port = listener.local_addr().expect("addr").port();
	drop(listener);
	format!("http://127.0.0.1:{port}")
}

fn base() -> HttpsUrl {
	HttpsUrl::loopback_http(&closed()).expect("loopback url")
}

fn secret() -> ScopedSecret {
	ScopedSecret::new("example.org", SENTINEL)
}

async fn assert_url_free(provider: &str, client: &dyn DnsProvider) {
	let record = DnsRecord::new(
		"_dmarc.example.org",
		RecordKind::Txt,
		"v=DMARC1; p=none",
		3600,
	);
	let outcomes = [
		("list", client.list("example.org").await.err()),
		(
			"upsert",
			client.upsert("example.org", record.clone()).await.err(),
		),
		("delete", client.delete("example.org", record).await.err()),
	];
	for (operation, error) in outcomes {
		// Route 53 does not list a zone at all.
		if operation == "list" && error == Some(ProviderError::Unsupported) {
			continue;
		}
		let Some(ProviderError::Remote(message)) = error else {
			panic!("{provider} {operation}: not a transport error");
		};
		assert!(
			!message.contains("127.0.0.1"),
			"{provider} {operation} quotes the address: {message}"
		);
		assert!(
			!message.contains(SENTINEL),
			"{provider} {operation} quotes the credential: {message}"
		);
	}
}

#[tokio::test]
async fn no_provider_quotes_the_url_in_a_transport_error() {
	assert_url_free("bunny", &BunnyProvider::new(secret()).with_base(base())).await;
	assert_url_free(
		"cloudflare",
		&CloudflareProvider::new(secret()).with_base(base()),
	)
	.await;
	assert_url_free("desec", &DesecProvider::new(secret()).with_base(base())).await;
	assert_url_free(
		"digitalocean",
		&DigitaloceanProvider::new(secret()).with_base(base()),
	)
	.await;
	assert_url_free(
		"dnsimple",
		&DnsimpleProvider::new(secret(), "1").with_base(base()),
	)
	.await;
	assert_url_free(
		"godaddy",
		&GodaddyProvider::new(SENTINEL.into(), SENTINEL.into(), "example.org".into())
			.with_base(base()),
	)
	.await;
	let namecheap =
		NamecheapProvider::new(ScopedSecret::new("example.org", format!("user:{SENTINEL}")))
			.expect("token")
			.with_client_ip(std::net::Ipv4Addr::new(192, 0, 2, 10))
			.with_api_url(base());
	assert_url_free("namecheap", &namecheap).await;
	assert_url_free(
		"ovh",
		&OvhProvider::new(SENTINEL.into(), SENTINEL.into(), secret()).with_base(base()),
	)
	.await;
	assert_url_free(
		"porkbun",
		&PorkbunProvider::new(secret(), SENTINEL).with_base(base()),
	)
	.await;
	assert_url_free(
		"route53",
		&Route53Provider::new(SENTINEL.into(), SENTINEL.into(), "Z123".into()).with_base(base()),
	)
	.await;
	assert_url_free(
		"spaceship",
		&SpaceshipProvider::new(SENTINEL.into(), SENTINEL.into(), "example.org".into())
			.with_base(base()),
	)
	.await;
	assert_url_free(
		"gcloud",
		&crate::dns::providers::gcloud::test_support::provider_for(&closed()),
	)
	.await;
}
