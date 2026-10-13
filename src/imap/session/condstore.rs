//! CONDSTORE enabling commands (RFC 7162 §3.1) and the MODSEQ value that
//! SEARCH reports when its criteria test mod-sequences (§3.1.5).

use super::super::command::{Command, FetchItem, ReturnOpt, SearchKey, StatusItem, Tagged};
use super::{Output, Session, State};

impl Session {
	/// Run `tagged`, and when it is the first CONDSTORE enabling command of
	/// the connection and succeeds, remember that CONDSTORE is on. If a
	/// mailbox was already selected, an untagged `OK [HIGHESTMODSEQ n]`
	/// goes before the command's own replies. SELECT and EXAMINE report
	/// HIGHESTMODSEQ themselves and so add nothing.
	pub(super) fn apply_enabling_condstore(&mut self, tagged: Tagged) -> Output {
		if self.condstore || !enables_condstore(&tagged.command) {
			return self.apply(tagged);
		}
		let announce = matches!(self.state, State::Selected { .. })
			&& !matches!(
				tagged.command,
				Command::Select { .. } | Command::Examine { .. }
			);
		let ok = format!("{} OK", tagged.tag);
		let mut output = self.apply(tagged);
		let lines = String::from_utf8_lossy(&output.bytes);
		if !lines.starts_with(&ok) && !lines.contains(&format!("\n{ok}")) {
			return output;
		}
		self.condstore = true;
		if announce && let State::Selected { snapshot, .. } = &self.state {
			let line = format!(
				"* OK [HIGHESTMODSEQ {}] highest mod-sequence\r\n",
				snapshot.highest_modseq()
			);
			output.bytes.splice(0..0, line.into_bytes());
		}
		output
	}
}

/// Whether `command` is a CONDSTORE enabling command (RFC 7162 §3.1): FETCH
/// with MODSEQ or CHANGEDSINCE, STORE with UNCHANGEDSINCE, a search whose
/// criteria use MODSEQ, SELECT or EXAMINE with QRESYNC, STATUS with
/// HIGHESTMODSEQ, and ENABLE CONDSTORE or QRESYNC.
fn enables_condstore(command: &Command) -> bool {
	match command {
		Command::Fetch {
			items,
			changed_since,
			..
		} => changed_since.is_some() || items.contains(&FetchItem::ModSeq),
		Command::Store {
			unchanged_since, ..
		} => unchanged_since.is_some(),
		Command::Search { criteria, .. }
		| Command::Esearch { criteria, .. }
		| Command::Sort { criteria, .. }
		| Command::Thread { criteria, .. } => uses_modseq(criteria),
		Command::Select { qresync, .. } | Command::Examine { qresync, .. } => qresync.is_some(),
		Command::Status { items, .. } => items.contains(&StatusItem::HighestModseq),
		Command::Enable { capabilities } => capabilities
			.iter()
			.any(|c| c.eq_ignore_ascii_case("CONDSTORE") || c.eq_ignore_ascii_case("QRESYNC")),
		_ => false,
	}
}

/// Whether any key in `criteria`, at any depth, is MODSEQ.
pub(super) fn uses_modseq(criteria: &[SearchKey]) -> bool {
	criteria.iter().any(|key| match key {
		SearchKey::ModSeq(_) => true,
		SearchKey::Not(inner) => uses_modseq(std::slice::from_ref(inner)),
		SearchKey::Or(a, b) => {
			uses_modseq(std::slice::from_ref(a)) || uses_modseq(std::slice::from_ref(b))
		}
		SearchKey::And(keys) => uses_modseq(keys),
		_ => false,
	})
}

/// The MODSEQ a SEARCH reply carries (RFC 7162 §3.1.5, RFC 4731 §3.2):
/// the highest mod-sequence among the messages the reply returns. When only
/// MIN and/or MAX are requested those are the first and last match, else
/// every match counts. `modseqs` follows the ascending order of the hits;
/// `None` when nothing matched.
pub(super) fn reply_modseq(modseqs: &[u64], opts: Option<&[ReturnOpt]>) -> Option<u64> {
	let only_extremes = opts.is_some_and(|opts| {
		!opts
			.iter()
			.any(|o| matches!(o, ReturnOpt::All | ReturnOpt::Count | ReturnOpt::Save))
	});
	if !only_extremes {
		return modseqs.iter().copied().max();
	}
	let opts = opts.unwrap_or_default();
	let first = modseqs.first().filter(|_| opts.contains(&ReturnOpt::Min));
	let last = modseqs.last().filter(|_| opts.contains(&ReturnOpt::Max));
	first.into_iter().chain(last).copied().max()
}

#[cfg(test)]
mod tests {
	use super::reply_modseq;
	use crate::imap::command::ReturnOpt;

	#[test]
	fn reply_modseq_covers_the_returned_messages() {
		let modseqs = [5, 9, 7];
		assert_eq!(reply_modseq(&modseqs, None), Some(9));
		assert_eq!(reply_modseq(&modseqs, Some(&[ReturnOpt::Min])), Some(5));
		assert_eq!(reply_modseq(&modseqs, Some(&[ReturnOpt::Max])), Some(7));
		assert_eq!(
			reply_modseq(&modseqs, Some(&[ReturnOpt::Min, ReturnOpt::Max])),
			Some(7)
		);
		assert_eq!(reply_modseq(&modseqs, Some(&[ReturnOpt::Count])), Some(9));
		assert_eq!(reply_modseq(&[], Some(&[ReturnOpt::All])), None);
	}
}
