//! F03: two changes made at the same time to one zone must both survive.
//!
//! `setHosts` replaces the whole host list, so a change that is read, edited
//! and written back while another does the same erases the other. The fake
//! server lets two readers see the same snapshot if they ask together, and
//! applies the writes in either order. A change someone makes outside this
//! process between a read and its write cannot be detected through this API,
//! so it is not part of what the provider can promise.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Form, State};
use tokio::sync::{Notify, mpsc, oneshot};

use super::base::{OK_XML, SentHost, SetHostsCall, txt, xml_response};
use super::*;

const ZONE: &str = "example.org";
const CHALLENGE: &str = "_acme-challenge.example.org";
type Write = (Vec<SentHost>, oneshot::Sender<()>);

struct Zone {
	hosts: Mutex<Vec<SentHost>>,
	reads: std::sync::atomic::AtomicUsize,
	together: Notify,
	writes: mpsc::UnboundedSender<Write>,
}

fn host(name: &str, kind: &str, value: &str) -> SentHost {
	SentHost {
		name: name.into(),
		kind: kind.into(),
		address: value.into(),
		ttl: Some("3600".into()),
		mx_pref: (kind == "MX").then(|| "10".into()),
	}
}

fn snapshot(hosts: &[SentHost]) -> String {
	let hosts: String = hosts
		.iter()
		.map(|h| {
			format!(
				r#"<host Name="{}" Type="{}" Address="{}" TTL="3600" MXPref="10"/>"#,
				h.name,
				h.kind,
				quick_xml::escape::escape(&h.address),
			)
		})
		.collect();
	format!(
		r#"<ApiResponse Status="OK"><Errors/><CommandResponse><DomainDNSGetHostsResult>{hosts}</DomainDNSGetHostsResult></CommandResponse></ApiResponse>"#
	)
}

async fn handle(
	State(zone): State<Arc<Zone>>,
	Form(params): Form<HashMap<String, String>>,
) -> axum::http::Response<String> {
	match params["Command"].as_str() {
		"namecheap.domains.dns.getHosts" => {
			let xml = snapshot(&zone.hosts.lock().unwrap());
			// If both callers ask together they own the same snapshot before
			// either can write; a provider that serialises them never gets here
			// twice at once, so the wait gives up.
			if zone.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
				let _ = tokio::time::timeout(Duration::from_millis(300), zone.together.notified())
					.await;
			} else {
				zone.together.notify_waiters();
			}
			xml_response(200, &xml)
		}
		"namecheap.domains.dns.setHosts" => {
			let hosts = SetHostsCall { params }.hosts();
			let (done, wait) = oneshot::channel();
			zone.writes.send((hosts, done)).unwrap();
			wait.await.unwrap();
			xml_response(200, OK_XML)
		}
		other => panic!("unexpected Namecheap command {other}"),
	}
}

async fn race(withdraw: bool, reverse: bool) -> Vec<SentHost> {
	let mut initial = vec![
		host("@", "MX", "mail.example.org"),
		host("@", "TXT", "v=spf1 -all"),
	];
	if withdraw {
		initial.push(host("_acme-challenge", "TXT", "old-token"));
	}
	let (send, mut writes) = mpsc::unbounded_channel();
	let zone = Arc::new(Zone {
		hosts: Mutex::new(initial.clone()),
		reads: std::sync::atomic::AtomicUsize::new(0),
		together: Notify::new(),
		writes: send,
	});
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let url = format!("http://{}/xml.response", listener.local_addr().unwrap());
	let app = axum::Router::new()
		.route("/xml.response", axum::routing::post(handle))
		.with_state(zone.clone());
	let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	let provider = NamecheapProvider::new(ScopedSecret::new(ZONE, "user:key"))
		.unwrap()
		.with_client_ip(std::net::Ipv4Addr::LOCALHOST)
		.with_api_url(HttpsUrl::loopback_http(&url).unwrap());
	let left = async {
		if withdraw {
			provider.delete(ZONE, txt(CHALLENGE, "old-token")).await
		} else {
			provider.upsert(ZONE, txt(CHALLENGE, "token-a")).await
		}
	};
	let right = provider.upsert(ZONE, txt(CHALLENGE, "token-b"));
	let apply = async {
		let first = writes.recv().await.expect("first replacement");
		let second = tokio::time::timeout(Duration::from_millis(500), writes.recv())
			.await
			.ok()
			.flatten();
		let Some(second) = second else {
			// The provider let one change finish before the next began.
			*zone.hosts.lock().unwrap() = first.0;
			first.1.send(()).unwrap();
			let (hosts, done) = writes.recv().await.expect("second replacement");
			*zone.hosts.lock().unwrap() = hosts;
			done.send(()).unwrap();
			return;
		};
		let is_left = |w: &Write| {
			if withdraw {
				!w.0.iter().any(|h| h.address == "token-b")
			} else {
				w.0.iter().any(|h| h.address == "token-a")
			}
		};
		let (left, right) = if is_left(&first) {
			(first, second)
		} else {
			(second, first)
		};
		for (hosts, done) in if reverse {
			[right, left]
		} else {
			[left, right]
		} {
			// The documented setHosts semantics replace, rather than merge.
			*zone.hosts.lock().unwrap() = hosts;
			done.send(()).unwrap();
		}
	};
	let outcome = tokio::time::timeout(Duration::from_secs(5), async {
		tokio::join!(left, right, apply)
	})
	.await;
	server.abort();
	let (left, right, ()) = outcome.expect("race must complete within 5 seconds");
	assert!(
		left.is_ok() && right.is_ok(),
		"unexpected provider errors: {left:?}, {right:?}"
	);
	let final_zone = zone.hosts.lock().unwrap().clone();
	for unchanged in initial.iter().filter(|h| h.name == "@") {
		assert!(
			final_zone.contains(unchanged),
			"unrelated MX/SPF lost: {final_zone:?}"
		);
	}
	final_zone
}

#[tokio::test]
async fn hostile_f03_concurrent_legacy_writes_preserve_zone() {
	let mut losses = Vec::new();
	for withdraw in [false, true] {
		for reverse in [false, true] {
			let zone = race(withdraw, reverse).await;
			let has = |value: &str| zone.iter().any(|h| h.address == value);
			if !has("token-b") || (!withdraw && !has("token-a")) || (withdraw && has("old-token")) {
				losses.push(format!("withdraw={withdraw}, reverse={reverse}: {zone:?}"));
			}
		}
	}
	assert!(
		losses.is_empty(),
		"successful legacy writes silently lost concurrent edits:\n{}",
		losses.join("\n")
	);
}
