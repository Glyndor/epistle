//! The zone and the record ids are data in the request path: characters that
//! mean something in a URL must not change which resource the keys reach.

use super::*;
use crate::dns::uri_probe::probe;

#[tokio::test]
async fn zone_and_record_id_are_escaped_path_segments() {
	let (base, seen) = probe(&[
		r#"{"status":"SUCCESS","records":[{"id":"7/../8?x","name":"x.a/b?c.org","type":"A","content":"192.0.2.1","ttl":"300","prio":"0"}]}"#,
		r#"{"status":"SUCCESS"}"#,
	])
	.await;
	let zone = "a/b?c.org";
	let provider = PorkbunProvider::new(ScopedSecret::new(zone, "sk"), "pk").with_base(base);
	provider
		.delete(
			zone,
			DnsRecord {
				name: format!("x.{zone}"),
				kind: RecordKind::A,
				value: String::new(),
				ttl: 300,
			},
		)
		.await
		.expect("delete");
	assert_eq!(
		*seen.lock().unwrap(),
		[
			"POST /dns/retrieve/a%2Fb%3Fc.org",
			"POST /dns/delete/a%2Fb%3Fc.org/7%2F..%2F8%3Fx"
		]
	);
}
