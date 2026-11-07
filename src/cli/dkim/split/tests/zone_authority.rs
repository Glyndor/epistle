//! The zone's own nameservers, as a test can make them.
//!
//! The fake answers with what the provider published (the zone the harness
//! writes into), so a test can say "the zone serves the record" without
//! knowing the key the run created.

use super::harness::Zone;

/// The zone's authoritative servers.
pub(super) struct ZoneAuthority {
	/// The zone they serve.
	pub zone: Zone,
	/// How many of them the zone has.
	pub servers: usize,
	/// How many of them do not answer at all.
	pub silent: usize,
	/// Whether they serve the records at all.
	pub blind: bool,
	/// Whether only one of them serves the records and the rest answer
	/// without them: the zone is still propagating.
	pub partial: bool,
}

impl ZoneAuthority {
	/// The zone's servers, all of them answering.
	#[allow(dead_code)]
	pub(super) fn new(zone: Zone) -> ZoneAuthority {
		ZoneAuthority {
			zone,
			servers: 2,
			silent: 0,
			blind: false,
			partial: false,
		}
	}
}

impl crate::dns::authoritative::AuthorityLookup for ZoneAuthority {
	fn txt<'a>(&'a self, name: &'a str) -> crate::dns::authoritative::TxtLookup<'a> {
		let values = if self.blind {
			Vec::new()
		} else {
			self.zone
				.records
				.lock()
				.unwrap()
				.get(name)
				.cloned()
				.unwrap_or_default()
		};
		let (servers, silent, partial) = (self.servers, self.silent, self.partial);
		Box::pin(async move {
			let mut answers = Vec::new();
			for index in 0..servers.saturating_sub(silent) {
				// With `partial` only the first server has the record: the
				// others answer, and answer without it.
				let served = if partial && index > 0 {
					Vec::new()
				} else {
					values.clone()
				};
				answers.push(served);
			}
			Some(crate::dns::authoritative::Authority {
				servers,
				answers,
				silent,
			})
		})
	}
}
