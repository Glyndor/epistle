//! ARC adapters and wire mutations layered on the unchanged DKIM harness.

use super::harness::*;
use epistle::arc::{ams, chain, seal, signature, validate};
use epistle::dkim::DkimOutcome;
use std::future::Future;
use std::sync::atomic::Ordering;

impl Dns {
	pub fn arc(name: &str) -> Self {
		let mut dns = Self::one("ams._domainkey.example.test", &record(name));
		dns.records.insert(
			"seal._domainkey.example.test".into(),
			vec![text(&format!("{name}.seal.dns")).trim().to_string()],
		);
		dns
	}
}

fn run<F: Future>(future: F) -> F::Output {
	tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.expect("runtime")
		.block_on(future)
}

pub fn arc(raw: Vec<u8>, dns: Dns) -> (chain::ChainValidation, usize) {
	bounded(move || {
		let result = run(validate::validate(&dns, &raw));
		(result, dns.calls.load(Ordering::SeqCst))
	})
}

pub fn ams_result(raw: Vec<u8>, dns: Dns) -> (DkimOutcome, usize) {
	bounded(move || {
		let instances = chain::extract(&raw)
			.expect("structural chain")
			.expect("ARC present");
		let newest = instances.last().expect("instance");
		let parsed =
			signature::parse_message_signature(&newest.message_signature).expect("AMS parses");
		let result = run(ams::verify(&dns, &parsed, &newest.message_signature, &raw));
		(result, dns.calls.load(Ordering::SeqCst))
	})
}

pub fn seal_result(raw: Vec<u8>, dns: Dns) -> (DkimOutcome, usize) {
	bounded(move || {
		let instances = chain::extract(&raw)
			.expect("structural chain")
			.expect("ARC present");
		let newest = instances.last().expect("instance");
		let parsed = signature::parse_seal(&newest.seal).expect("seal parses");
		let result = run(seal::verify(&dns, &parsed, &newest.seal, &instances));
		(result, dns.calls.load(Ordering::SeqCst))
	})
}

/// Replace one tag in the first signature, preserving the rest of the wire data.
pub fn tag(raw: &[u8], key: &str, value: &str) -> Vec<u8> {
	let raw = std::str::from_utf8(raw).expect("ASCII message");
	let end = raw.find("\r\n").expect("fixture signature line");
	let (head, tail) = raw.split_at(end);
	let prefix = format!("{key}=");
	let mut changed = false;
	let head = head
		.split(';')
		.map(|part| {
			let trimmed = part.trim_start();
			if trimmed.starts_with(&prefix) {
				changed = true;
				format!("{}{prefix}{value}", &part[..part.len() - trimmed.len()])
			} else {
				part.to_string()
			}
		})
		.collect::<Vec<_>>()
		.join(";");
	assert!(changed, "missing fixture tag {key}");
	format!("{head}{tail}").into_bytes()
}
