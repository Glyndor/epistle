//! The queue adapter: the SRS addresses a run signs.

/// The secret every run signs SRS addresses with. It is fixed, so a crash
/// reproduces, and it protects nothing: the addresses it signs are never
/// sent anywhere.
const SRS_SECRET: &[u8] = b"epistle-fuzz-srs-secret";

/// The day the SRS addresses of a run pretend it is. The timestamp of an
/// address wraps every 1024 days, so a fixed day keeps every run on the
/// same timestamp and the addresses of a run compare with each other.
const SRS_DAY: u64 = 19_000;

/// The domain the SRS addresses of a run are for.
const SRS_RELAY: &str = "relay.example";

/// The local part of an address the rewriter signed.
fn srs_local_part(address: &str) -> &str {
	match address.strip_suffix(SRS_RELAY) {
		Some(local) => local.strip_suffix('@').unwrap_or(local),
		None => address,
	}
}

/// The same local part with its prefix in lower case. The prefix is matched
/// without regard to case, so the rewriter takes it for the same address.
fn srs_lower_prefix(local_part: &str) -> String {
	match local_part.strip_prefix("SRS0") {
		Some(rest) => format!("srs0{rest}"),
		None => local_part.to_string(),
	}
}

/// The SRS rewriter, driven by what a client sent: an address to reverse and
/// a sender to sign and reverse again.
///
/// `sent` is the local part of an address a client sent, `local` and
/// `domain` the sender a run makes up, and `hosted` the domain an address
/// names. Every address is reversed twice, plain and naming a hosted
/// domain, and the sender is signed and reversed again twice.
///
/// # Panics
///
/// When the rewriter reverses an address to a pair it would not sign again,
/// or when an address it signs does not reverse to the pair it hides. Both
/// are the same defect seen from its two ends.
pub fn srs_reverse(sent: &str, local: &str, domain: &str, hosted: &str) {
	let srs = crate::queue::srs::Srs::new(SRS_SECRET);
	for hosted_domain in [None, Some(hosted)] {
		let reversed = match hosted_domain {
			Some(name) => srs.reverse_for(name, sent, SRS_DAY, 0),
			None => srs.reverse(sent, SRS_DAY, 0),
		};
		let Some((local, domain)) = reversed else {
			continue;
		};
		// The address the rewriter signs for the pair it gave back must be
		// the address it reversed. The prefix is matched without regard to
		// case, and the timestamp with it, so the two may differ in the
		// case of the prefix alone.
		let signed = match hosted_domain {
			Some(name) => {
				srs.forward_for(name, (local.as_str(), domain.as_str()), SRS_RELAY, SRS_DAY)
			}
			None => srs.forward(local.as_str(), domain.as_str(), SRS_RELAY, SRS_DAY),
		};
		assert!(
			srs_local_part(&signed).eq_ignore_ascii_case(sent),
			"the rewriter does not sign the pair it gave back: {signed}"
		);
	}
	for hosted_domain in [None, Some(hosted)] {
		let signed = match hosted_domain {
			Some(name) => srs.forward_for(name, (local, domain), SRS_RELAY, SRS_DAY),
			None => srs.forward(local, domain, SRS_RELAY, SRS_DAY),
		};
		let signed_local = srs_local_part(&signed);
		let reversed = match hosted_domain {
			Some(name) => srs.reverse_for(name, signed_local, SRS_DAY, 0),
			None => srs.reverse(signed_local, SRS_DAY, 0),
		};
		assert_eq!(
			reversed,
			Some((local.to_string(), domain.to_string())),
			"the rewriter does not reverse the pair it signed"
		);
		// The prefix in lower case names the same address, and the pair
		// behind it is the same one.
		let lowered = srs_lower_prefix(signed_local);
		let reversed = match hosted_domain {
			Some(name) => srs.reverse_for(name, &lowered, SRS_DAY, 0),
			None => srs.reverse(&lowered, SRS_DAY, 0),
		};
		assert_eq!(
			reversed,
			Some((local.to_string(), domain.to_string())),
			"the rewriter does not reverse the pair it signed"
		);
	}
}
