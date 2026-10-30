//! The `Comment` field Bunny records carry on create and on update. Split
//! from `tests.rs` to keep that file under the line limit.

use super::*;

#[tokio::test]
async fn create_body_carries_the_comment_field() {
	let (provider, state) = mock().await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let body: serde_json::Value = serde_json::from_str(&state.lock().unwrap().bodies[0]).unwrap();
	assert_eq!(body["Comment"], expected_description());
}

#[tokio::test]
async fn update_body_carries_the_comment_field() {
	let (provider, state) = mock().await;
	state.lock().unwrap().have_dmarc = true;
	provider
		.upsert(
			"example.org",
			txt("_dmarc.example.org", "v=DMARC1; p=reject"),
		)
		.await
		.expect("upsert");
	let s = state.lock().unwrap();
	assert_eq!(s.calls.last().unwrap(), "POST /dnszone/42/records/1001");
	let body: serde_json::Value = serde_json::from_str(s.bodies.last().unwrap()).unwrap();
	assert_eq!(body["Comment"], expected_description());
}

/// The exact string the owner expects in the provider panel.
fn expected_description() -> String {
	format!("Epistle v{}", env!("CARGO_PKG_VERSION"))
}
