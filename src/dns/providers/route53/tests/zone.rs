//! A Route 53 hosted zone that keeps its record sets and applies a change
//! batch as the API does: all of it or none of it, a `DELETE` that must name
//! the set with its TTL and every value, and a `CREATE` refused where the set
//! exists. A refusal is the `InvalidChangeBatch` answer. `race` swaps the zone
//! after the provider read it and before its batch arrives, the change another
//! account makes in that moment.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Query, State};
use axum::routing::post;

use super::*;

/// One record set: name with its trailing dot, type, TTL and values as
/// listed. `extra` goes inside the `<ResourceRecordSet>` as it is (an
/// `<AliasTarget>` or a `<SetIdentifier>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Set {
	pub(super) name: String,
	pub(super) kind: String,
	pub(super) ttl: u32,
	pub(super) values: Vec<String>,
	pub(super) extra: String,
}

/// A plain set.
pub(super) fn set(name: &str, kind: &str, values: &[&str]) -> Set {
	Set {
		name: name.to_string(),
		kind: kind.to_string(),
		ttl: 300,
		values: values.iter().map(|v| v.to_string()).collect(),
		extra: String::new(),
	}
}

#[derive(Default)]
pub(super) struct Zone {
	pub(super) sets: Vec<Set>,
	/// What the zone becomes when the next batch arrives, before it applies.
	pub(super) race: Option<Vec<Set>>,
	/// Every batch received, applied or not.
	pub(super) batches: Vec<String>,
	/// How many sets one page holds; `None` for one page.
	pub(super) page: Option<usize>,
	/// The query of every listing request, in order.
	pub(super) queries: Vec<String>,
}

pub(super) type Held = Arc<Mutex<Zone>>;

fn set_xml(set: &Set) -> String {
	let values: String = set
		.values
		.iter()
		.map(|v| format!("<ResourceRecord><Value>{v}</Value></ResourceRecord>"))
		.collect();
	let records = if set.values.is_empty() {
		String::new()
	} else {
		format!(
			"<TTL>{}</TTL><ResourceRecords>{values}</ResourceRecords>",
			set.ttl
		)
	};
	format!(
		"<ResourceRecordSet><Name>{}</Name><Type>{}</Type>{}{records}</ResourceRecordSet>",
		set.name, set.kind, set.extra
	)
}

fn page_xml(sets: &[Set], next: Option<&Set>) -> String {
	let body: String = sets.iter().map(set_xml).collect();
	let tail = match next {
		Some(next) => format!(
			"<IsTruncated>true</IsTruncated><NextRecordName>{}</NextRecordName>\
<NextRecordType>{}</NextRecordType>",
			next.name, next.kind
		),
		None => "<IsTruncated>false</IsTruncated>".to_string(),
	};
	format!(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListResourceRecordSetsResponse>\
<ResourceRecordSets>{body}</ResourceRecordSets>{tail}</ListResourceRecordSetsResponse>"
	)
}

async fn list(
	State(zone): State<Held>,
	uri: axum::http::Uri,
	Query(query): Query<std::collections::HashMap<String, String>>,
) -> String {
	let mut zone = zone.lock().unwrap();
	zone.queries.push(uri.query().unwrap_or("").to_string());
	let name = query.get("name").cloned();
	let kind = query.get("type").cloned();
	// The apex lookup: one set, starting at the SOA of a name. The zone
	// answers with that set when the name holds it, and with none otherwise.
	if kind.as_deref() == Some("SOA") {
		let found: Vec<Set> = zone
			.sets
			.iter()
			.filter(|s| Some(&s.name) == name.as_ref() && s.kind == "SOA")
			.cloned()
			.collect();
		return page_xml(&found, None);
	}
	let from = match (&name, &kind) {
		(Some(name), Some(kind)) => zone
			.sets
			.iter()
			.position(|s| &s.name == name && &s.kind == kind)
			.unwrap_or(zone.sets.len()),
		_ => 0,
	};
	let size = zone.page.unwrap_or(usize::MAX);
	let rest = &zone.sets[from..];
	let shown = &rest[..rest.len().min(size)];
	page_xml(shown, rest.get(size))
}

/// The text between `<tag>` and `</tag>` from `at`.
fn between<'a>(text: &'a str, tag: &str) -> Option<&'a str> {
	let open = format!("<{tag}>");
	let start = text.find(&open)? + open.len();
	let end = text[start..].find(&format!("</{tag}>"))? + start;
	Some(&text[start..end])
}

fn parse_change(change: &str) -> (String, Set) {
	let action = between(change, "Action").unwrap().to_string();
	let values = change
		.split("<Value>")
		.skip(1)
		.map(|rest| rest[..rest.find("</Value>").unwrap()].to_string())
		.collect();
	let set = Set {
		name: between(change, "Name").unwrap().to_string(),
		kind: between(change, "Type").unwrap().to_string(),
		ttl: between(change, "TTL").unwrap().parse().unwrap(),
		values,
		extra: String::new(),
	};
	(action, set)
}

fn refusal(message: &str) -> axum::http::Response<String> {
	axum::http::Response::builder()
		.status(400)
		.body(format!(
			"<?xml version=\"1.0\"?><InvalidChangeBatch \
xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><Messages><Message>{message}\
</Message></Messages></InvalidChangeBatch>"
		))
		.unwrap()
}

async fn change(State(zone): State<Held>, body: String) -> axum::http::Response<String> {
	let mut zone = zone.lock().unwrap();
	zone.batches.push(body.clone());
	if let Some(raced) = zone.race.take() {
		zone.sets = raced;
	}
	let mut sets = zone.sets.clone();
	for chunk in body.split("<Change>").skip(1) {
		let (action, wanted) = parse_change(chunk);
		let at = sets
			.iter()
			.position(|s| s.name == wanted.name && s.kind == wanted.kind);
		let label = format!("[name='{}', type='{}']", wanted.name, wanted.kind);
		match (action.as_str(), at) {
			("DELETE", Some(i)) if sets[i] == wanted => {
				sets.remove(i);
			}
			("DELETE", Some(_)) => {
				return refusal(&format!(
					"Tried to delete resource record set {label} but the values provided do not match the current values"
				));
			}
			("DELETE", None) => {
				return refusal(&format!(
					"Tried to delete resource record set {label} but it was not found"
				));
			}
			("CREATE", Some(_)) => {
				return refusal(&format!(
					"Tried to create resource record set {label} but it already exists"
				));
			}
			("CREATE", None) => sets.push(wanted),
			(other, _) => panic!("the guarded write sent {other}"),
		}
	}
	zone.sets = sets;
	axum::http::Response::builder()
		.status(200)
		.body("<ChangeResourceRecordSetsResponse/>".to_string())
		.unwrap()
}

/// A provider over a zone that holds `sets`.
pub(super) async fn start(sets: Vec<Set>) -> (Route53Provider, Held) {
	let zone: Held = Arc::new(Mutex::new(Zone {
		sets,
		..Zone::default()
	}));
	let app = Router::new()
		.route("/2013-04-01/hostedzone/{id}/rrset", post(change).get(list))
		.with_state(zone.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = Route53Provider::new("AKIA".into(), "secret".into(), "Z123".into())
		.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap());
	(provider, zone)
}

/// The apex of the zone every case uses: its SOA and NS.
pub(super) fn apex() -> Vec<Set> {
	vec![
		set(
			"example.org.",
			"SOA",
			&["ns-1.awsdns-01.org. hostmaster.example.org. 1 7200 900 1209600 86400"],
		),
		set("example.org.", "NS", &["ns-1.awsdns-01.org."]),
	]
}
