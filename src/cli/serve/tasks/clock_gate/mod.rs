//! The time a task that deletes may act on.
//!
//! A purge on a wrong clock cannot be undone, so a task that removes mail
//! does not read the wall clock raw. It asks the shared time reference
//! ([`crate::evidence::timeref`]) and, when the reading is not believed,
//! skips the run and says so once.

use crate::evidence::timeref::Reading;

/// The time to judge age by, or `None` when the clock is not believed. `warned`
/// remembers whether the skip was already logged, so a stopped clock logs once
/// and its return logs once.
pub(super) fn believed(reading: Reading, warned: &mut bool, task: &str) -> Option<u64> {
	if reading.sound {
		if std::mem::take(warned) {
			tracing::info!(task, "the clock is believed again, so the task runs");
		}
		return Some(reading.cautious());
	}
	if !*warned {
		*warned = true;
		tracing::warn!(
			task,
			"the clock is not believed, so the task removes nothing until it is"
		);
	}
	None
}

#[cfg(test)]
mod tests;
