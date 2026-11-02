//! The grace periods around sealing and timestamping, and the window a token
//! must fall in.

use crate::evidence::checkpoint;
use crate::evidence::day::Day;

/// Grace after midnight before a missing checkpoint is a break: the server
/// seals closed days on a timer.
pub const SEAL_GRACE_SECS: u64 = 3600;
/// The latest a token may be issued after its checkpoint was made.
pub const TOKEN_GRACE_SECS: u64 = 3 * 86_400;

/// The times a token for `day`'s checkpoint may carry: after the day ended
/// (every record of the day existed) and within [`TOKEN_GRACE_SECS`] of the
/// seal. Shared by the audit and by the purge, which must not judge a token
/// by a looser rule than the audit does.
pub(crate) fn token_window(
	day: Day,
	checkpoint: &checkpoint::Checkpoint,
	stamp: &crate::evidence::tsa::Stamp,
) -> Result<(), &'static str> {
	if stamp.gen_time < Day(day.0 + 1).start_epoch() {
		return Err("the token predates the end of the day");
	}
	if stamp.gen_time > checkpoint.created.saturating_add(TOKEN_GRACE_SECS) {
		return Err("the token was issued more than 3 days after the checkpoint");
	}
	Ok(())
}
