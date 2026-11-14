//! Who a job comes from, as the keys its budget is counted under.

use std::net::IpAddr;

/// Longest domain kept in a key; a longer one is cut.
pub(super) const MAX_DOMAIN_LEN: usize = 255;

/// Who a job comes from, as the keys its budget is counted under.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrainSource {
	/// The client's own block, the wider block around it, and its network.
	pub(super) addresses: Option<(String, String, String)>,
	/// The sender's domain, only when the server verified it.
	pub(super) domain: Option<String>,
}

impl TrainSource {
	/// The source of a message: the client address, and the envelope sender's
	/// domain when (and only when) the server verified it, which the caller
	/// says by passing `verified_domain`. Either may be missing; with neither
	/// the job has no source and only the queue and the global count bound it.
	pub fn new(client: Option<IpAddr>, verified_domain: Option<&str>) -> Self {
		let addresses = client.map(|ip| match ip {
			IpAddr::V4(v4) => {
				let [a, b, c, _] = v4.octets();
				(
					format!("{v4}"),
					format!("{a}.{b}.{c}.0/24"),
					format!("{a}.{b}.0.0/16"),
				)
			}
			IpAddr::V6(v6) => {
				let [a, b, c, d, ..] = v6.segments();
				(
					format!("{a:x}:{b:x}:{c:x}:{d:x}::/64"),
					format!("{a:x}:{b:x}:{c:x}::/48"),
					format!("{a:x}:{b:x}::/32"),
				)
			}
		});
		let domain = verified_domain
			.filter(|domain| !domain.is_empty())
			.map(|domain| {
				let mut domain = domain.to_ascii_lowercase();
				if domain.len() > MAX_DOMAIN_LEN {
					let mut end = MAX_DOMAIN_LEN;
					while !domain.is_char_boundary(end) {
						end -= 1;
					}
					domain.truncate(end);
				}
				domain
			});
		TrainSource { addresses, domain }
	}

	/// No source: bounded by the queue and the global count alone.
	pub fn unattributed() -> Self {
		TrainSource::default()
	}
}
