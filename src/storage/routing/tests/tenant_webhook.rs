//! A message received for a tenant's domain is announced to that tenant's
//! webhook and to no other.

use super::*;
use crate::test_fixtures::fresh_secret;
use crate::webhook::tests::support::{bodies, quiet, settle, signed_receiver, tenant_config};

fn two_domains() -> DirectoryHandle {
	DirectoryHandle::new(crate::smtp::directory::Directory::new(
		[
			"a.example".to_string(),
			"b.example".to_string(),
			"c.example".to_string(),
		],
		[
			("alice@a.example".to_string(), "alice".to_string()),
			("bob@b.example".to_string(), "bob".to_string()),
			("carol@c.example".to_string(), "carol".to_string()),
		],
	))
}

fn mail_for(recipient: &str) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "origin@elsewhere.example".into(),
		recipients: vec![recipient.into()],
		data: b"Subject: ping\r\n\r\nhi\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: false,
		no_dsn: Vec::new(),
	}
}

#[tokio::test]
async fn a_received_message_is_announced_to_the_webhook_of_its_recipients_tenant() {
	let (default_url, default) = signed_receiver().await;
	let (alpha_url, alpha) = signed_receiver().await;
	let (beta_url, beta) = signed_receiver().await;
	let config = tenant_config(
		Some((&default_url, &fresh_secret())),
		Some((&alpha_url, &fresh_secret())),
		Some((&beta_url, &fresh_secret())),
	);
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = SplitDelivery::new(dir.path(), two_domains())
		.expect("sink")
		.with_webhook(Arc::new(
			crate::webhook::from_config(&config).expect("a poster"),
		));
	for recipient in ["alice@a.example", "bob@b.example", "carol@c.example"] {
		sink.deliver(mail_for(recipient)).expect("deliver");
	}
	settle(|| {
		!bodies(&alpha).is_empty() && !bodies(&beta).is_empty() && !bodies(&default).is_empty()
	})
	.await;
	quiet().await;
	let (alpha, beta, default) = (bodies(&alpha), bodies(&beta), bodies(&default));
	assert_eq!((alpha.len(), beta.len(), default.len()), (1, 1, 1));
	assert!(alpha[0].contains("alice@a.example"), "{}", alpha[0]);
	assert!(beta[0].contains("bob@b.example"), "{}", beta[0]);
	assert!(default[0].contains("carol@c.example"), "{}", default[0]);
}
