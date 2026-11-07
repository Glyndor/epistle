use super::harness::{Certificate, Peer, assert_status, exchange, request, slowloris};

const CONFIG: &str = "/mail/config-v1.1.xml?emailaddress=alice@example.org";
const DISCOVER: &str = "/autodiscover/autodiscover.xml";
const PROFILE: &str = "/mobileconfig?email=alice@example.org";

fn fixture() -> Peer {
	let router =
		crate::autodiscovery::router("mail.example.org".into(), vec!["example.org".into()]);
	Peer::start(|incoming| {
		crate::autodiscovery::serve_on(incoming, router, None, 8, Default::default())
	})
}

async fn healthy(peer: &Peer) {
	for (path, marker) in [
		(CONFIG, "<hostname>mail.example.org</hostname>"),
		(DISCOVER, "<Server>mail.example.org</Server>"),
		(
			"/autodiscover/autodiscover.json?Protocol=IMAP&Email=alice@example.org",
			"\"Server\":\"mail.example.org\"",
		),
		(PROFILE, "<string>alice@example.org</string>"),
	] {
		peer.healthy(peer.connect().await, path, marker).await;
	}
}

#[tokio::test]
async fn hostile_host_cannot_replace_xml_or_plist_hostname() {
	let peer = fixture();
	healthy(&peer).await;
	for path in [CONFIG, DISCOVER, PROFILE] {
		for host in [
			"evil<injected/>",
			"evil\"injected",
			"evil\r\nX-Injected: marker",
		] {
			let reply = exchange(peer.connect().await, &request(path, host)).await;
			assert_status(&reply, 200);
			assert!(
				reply.contains("mail.example.org"),
				"configured hostname lost"
			);
			for marker in ["evil", "injected", "marker"] {
				assert!(
					!reply.contains(marker),
					"Host reflected in public document: {reply}"
				);
			}
			healthy(&peer).await;
		}
		// A CR inside a field value, rather than a complete new header.
		let reply = exchange(peer.connect().await, &request(path, "evil\rbroken")).await;
		assert_status(&reply, 400);
		healthy(&peer).await;
	}
}

#[tokio::test]
async fn injected_email_cannot_add_xml_elements_or_plist_keys() {
	let peer = fixture();
	healthy(&peer).await;
	let email = "</string><key>Injected</key><string>\"&@example.org";
	let encoded: String = url::form_urlencoded::byte_serialize(email.as_bytes()).collect();
	for (path, parameter) in [
		("/mail/config-v1.1.xml", "emailaddress"),
		(DISCOVER, "email"),
		("/autodiscover/autodiscover.json", "Protocol=IMAP&Email"),
		("/mobileconfig", "email"),
	] {
		let reply = exchange(
			peer.connect().await,
			&request(&format!("{path}?{parameter}={encoded}"), "mail.example.org"),
		)
		.await;
		assert_status(&reply, 200);
		assert!(
			!reply.contains("<key>Injected</key>"),
			"email injected plist markup"
		);
		assert!(!reply.contains(email), "raw email reflected");
		if path == "/mobileconfig" {
			// Independent expected literal: do not call the production escape helper.
			assert!(
				reply.contains(
					"&lt;/string&gt;&lt;key&gt;Injected&lt;/key&gt;&lt;string&gt;&quot;&amp;@example.org"
				),
				"email was not XML escaped"
			);
		}
		healthy(&peer).await;
	}
}

#[tokio::test]
async fn control_characters_in_profile_email_are_bounded_400() {
	let peer = fixture();
	healthy(&peer).await;
	for email in [
		"alice%00@example.org",
		"alice%0D%0AX-Injected%3Ayes@example.org",
	] {
		let reply = exchange(
			peer.connect().await,
			&request(&format!("/mobileconfig?email={email}"), "mail.example.org"),
		)
		.await;
		assert_status(&reply, 400);
		assert!(!reply.contains("X-Injected"));
		healthy(&peer).await;
	}
}

#[tokio::test]
async fn dripping_plain_discovery_headers_close_by_deadline() {
	let peer = fixture();
	healthy(&peer).await;
	slowloris(peer.connect().await, CONFIG).await;
	healthy(&peer).await;
}

#[tokio::test]
async fn dripping_tls_discovery_headers_close_by_deadline() {
	let cert = Certificate::new();
	let tls = crate::tls::https::FileAcceptor::new(cert.tls.clone())
		.expect("TLS acceptor")
		.current();
	let router =
		crate::autodiscovery::router("mail.example.org".into(), vec!["example.org".into()]);
	let peer = Peer::start(|incoming| {
		crate::autodiscovery::serve_on(incoming, router, Some(tls), 8, Default::default())
	});
	peer.healthy(
		cert.connect(peer.connect().await).await,
		CONFIG,
		"mail.example.org",
	)
	.await;
	slowloris(cert.connect(peer.connect().await).await, CONFIG).await;
	peer.healthy(
		cert.connect(peer.connect().await).await,
		CONFIG,
		"mail.example.org",
	)
	.await;
}
