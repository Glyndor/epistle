//! The bounds and the helpers the fuzz adapters of every subsystem share.

/// The most bytes an input of the targets below is given: they read network
/// bodies and headers, which the listeners bound well under this.
pub(super) const INPUT_CAP: usize = 64 * 1024;

/// The largest index at most `max` that is a character boundary of `text`.
pub(super) fn floor_char_boundary(text: &str, max: usize) -> usize {
	let mut end = max.min(text.len());
	while !text.is_char_boundary(end) {
		end -= 1;
	}
	end
}
