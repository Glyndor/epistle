//! RFC 2136 provider tests, second half: what happens when the nameserver's
//! answer is not the one we asked for. Split from `rfc2136_tests.rs` to stay
//! under the per-file line limit; the mock harness lives in the first half.

use super::tests::{KEY_NAME, ServerReply, ZONE, provider_with_endpoint, spawn_server, txt};
use super::*;

use base64::Engine;
use hickory_resolver::proto::op::Message;
use hickory_resolver::proto::rr::TSigner;
use hickory_resolver::proto::rr::rdata::tsig::TsigAlgorithm;

/// A signer holding a key the provider does not have, for forging a response
/// that is signed but signed by the wrong party.
fn foreign_signer() -> TSigner {
	let key = base64::engine::general_purpose::STANDARD
		.decode("YW5vdGhlci1rZXktZW50aXJlbHktZm9yLWZvcmdlcnktdGVzdA==")
		.unwrap();
	let name = hickory_resolver::proto::rr::Name::from_ascii(KEY_NAME).unwrap();
	TSigner::new(key, TsigAlgorithm::HmacSha256, name, 300).unwrap()
}

#[tokio::test]
async fn a_response_signed_with_the_wrong_key_is_rejected() {
	// The whole point of verifying TSIG on the *response* is that an
	// off-path attacker who can answer first must not be able to make a
	// failed update look like NOERROR. This response says NOERROR and is
	// properly signed — just not by anyone holding our key.
	let signer = foreign_signer();
	let (endpoint, _captured) = spawn_server(move |_| ServerReply::NoError {
		verify_signer: signer.clone(),
	})
	.await;
	let provider = provider_with_endpoint(endpoint);
	let error = provider
		.upsert(ZONE, txt("_probe.example.org", "v=spf1 -all"))
		.await
		.expect_err("a response we cannot authenticate must not read as success");
	assert!(
		matches!(error, ProviderError::Auth),
		"expected Auth, got {error:?}"
	);
}

#[tokio::test]
async fn an_unsigned_response_is_rejected() {
	// Same control from the other side: no TSIG at all on the answer.
	let (endpoint, _captured) = spawn_server(|_| ServerReply::NotAuth).await;
	let provider = provider_with_endpoint(endpoint);
	let error = provider
		.upsert(ZONE, txt("_probe.example.org", "v=spf1 -all"))
		.await
		.expect_err("an unsigned response must not read as success");
	assert!(
		matches!(error, ProviderError::Auth),
		"expected Auth, got {error:?}"
	);
}

#[tokio::test]
async fn a_server_that_never_answers_is_a_remote_error_not_a_success() {
	// Connection accepted, nothing written back. Reading the length prefix
	// hits EOF; that must surface as an error rather than an empty success.
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let endpoint = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
	tokio::spawn(async move {
		while let Ok((stream, _)) = listener.accept().await {
			drop(stream);
		}
	});
	let provider = provider_with_endpoint(endpoint);
	let error = provider
		.upsert(ZONE, txt("_probe.example.org", "v=spf1 -all"))
		.await
		.expect_err("a truncated exchange is not a successful update");
	assert!(
		matches!(error, ProviderError::Remote(_)),
		"expected Remote, got {error:?}"
	);
}

#[tokio::test]
async fn a_closed_port_is_a_remote_error() {
	// Bind then drop, so the port is almost certainly free and refuses.
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let endpoint = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
	drop(listener);
	let provider = provider_with_endpoint(endpoint);
	let error = provider
		.delete(ZONE, txt("_probe.example.org", "v=spf1 -all"))
		.await
		.expect_err("a refused connection is not a successful delete");
	assert!(
		matches!(error, ProviderError::Remote(_)),
		"expected Remote, got {error:?}"
	);
}

#[tokio::test]
async fn a_message_larger_than_dns_over_tcp_allows_is_refused_before_dialling() {
	// The length prefix is a u16, so a body past 65535 cannot be framed. The
	// provider must say so rather than truncate the record silently.
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let endpoint = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
	drop(listener);
	let provider = provider_with_endpoint(endpoint);
	let huge = "x".repeat(70_000);
	let error = provider
		.upsert(ZONE, txt("_probe.example.org", &huge))
		.await
		.expect_err("an unframeable message is not a successful update");
	assert!(
		matches!(error, ProviderError::Remote(_)),
		"expected Remote, got {error:?}"
	);
}

#[tokio::test]
async fn garbage_on_the_wire_is_a_remote_error() {
	let (endpoint, _captured) = spawn_server(|_| ServerReply::Raw(vec![0xff; 12])).await;
	let provider = provider_with_endpoint(endpoint);
	let error = provider
		.upsert(ZONE, txt("_probe.example.org", "v=spf1 -all"))
		.await
		.expect_err("undecodable bytes are not a successful update");
	assert!(
		matches!(error, ProviderError::Auth | ProviderError::Remote(_)),
		"expected Auth or Remote, got {error:?}"
	);
}

/// Keep the unused-import lint quiet about `Message`, which the harness type
/// signature pulls in.
#[allow(dead_code)]
fn _message_type_is_referenced(_: Option<Message>) {}
