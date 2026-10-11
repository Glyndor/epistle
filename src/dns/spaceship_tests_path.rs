//! The zone is data in the request path and the paging cursor is data in the
//! query: characters that mean something in a URL must not change which
//! resource the key pair reaches.

use super::*;
use crate::dns::uri_probe::probe;

#[tokio::test]
async fn zone_is_one_escaped_segment_and_paging_is_encoded() {
	let (base, seen) = probe(&[r#"{"items":[],"total":0}"#]).await;
	let zone = "a/../b?c.org";
	let provider =
		SpaceshipProvider::new("k".to_string(), "s".to_string(), zone.to_string()).with_base(base);
	provider.list(zone).await.expect("list");
	assert_eq!(
		*seen.lock().unwrap(),
		["GET /dns/records/a%2F..%2Fb%3Fc.org?take=500&skip=0"]
	);
}
