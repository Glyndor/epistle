pub use super::*;

pub(super) mod base;
pub(super) mod select;

/// Expand with the default budget and keep only the occurrences. The tests
/// here do not care whether the expansion was clipped, so they read the
/// occurrences and leave the flag alone.
fn expand(dtstart: i64, rule: Option<&Rule>, window_start: i64, window_end: i64) -> Vec<i64> {
	super::expand_bounded(
		dtstart,
		rule,
		window_start,
		window_end,
		super::DEFAULT_BUDGET,
	)
	.0
}
