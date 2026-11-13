//! Rewrite the header block field by field, keeping or dropping each field
//! together with its folded continuation lines.

use super::{field_name, header_block_end};

/// `data` without the header fields `keep` does not want, folded
/// continuation lines included: a continuation is kept or dropped with the
/// field above it. The body and every other line are kept byte for byte.
pub(super) fn rewrite_header_block(data: &[u8], mut keep: impl FnMut(&[u8]) -> bool) -> Vec<u8> {
	let header_end = header_block_end(data);
	let mut out = Vec::with_capacity(data.len());
	let mut dropping = false;
	for line in data[..header_end].split_inclusive(|&b| b == b'\n') {
		let continuation = matches!(line.first(), Some(b' ' | b'\t'));
		if !continuation {
			dropping = field_name(line).is_some_and(|name| !keep(name));
		}
		if !dropping {
			out.extend_from_slice(line);
		}
	}
	out.extend_from_slice(&data[header_end..]);
	out
}

/// In-place header rewrite: keep the field when `keep` wants its name, drop
/// it otherwise, and move the body up over the space the dropped fields
/// leave. Saves the body copy the slice-returning variants force. The buffer
/// grows up to `data.len()` once; nothing is reallocated when no field is
/// dropped.
pub(super) fn rewrite_header_block_in_place(
	data: &mut Vec<u8>,
	mut keep: impl FnMut(&[u8]) -> bool,
) {
	let header_end = header_block_end(data);
	// Pre-compute the kept lines' (original start, length) so the
	// in-place copy can read from the right place in the original
	// buffer even after earlier lines have been moved down. The
	// structure mirrors the slice-returning `rewrite_header_block`:
	// walk the header block line by line, drop the right ones, and
	// keep a list of (kept_offset, kept_length) pairs to copy
	// afterwards.
	struct Kept {
		offset: usize,
		length: usize,
	}
	let mut kept: Vec<Kept> = Vec::new();
	let mut dropping = false;
	let mut cursor = 0usize;
	while cursor < header_end {
		let line_start = cursor;
		let mut line_end = line_start;
		while line_end < header_end && data[line_end] != b'\n' {
			line_end += 1;
		}
		if line_end < header_end {
			line_end += 1; // include the LF
		}
		let line = &data[line_start..line_end];
		let continuation = matches!(line.first(), Some(b' ' | b'\t'));
		if !continuation {
			dropping = field_name(line).is_some_and(|name| !keep(name));
		}
		if !dropping {
			kept.push(Kept {
				offset: line_start,
				length: line.len(),
			});
		}
		cursor = line_end;
	}
	// Compact: copy every kept line to its new offset, then move
	// the body up to follow. Forward iteration with forward
	// copies works because the kept lines' sources are
	// monotonically increasing and each destination lies below
	// the next source: the first copy reads from [0, len) and
	// writes to [0, len) (no-op), the second reads from a
	// higher range and writes below it, and so on. When the
	// destination range overlaps the source (which happens when
	// the kept line sits in the same offset range as the next
	// kept line, with the dropped bytes in between), the
	// destination is below the source so a forward copy reads
	// from the source before any write touches it.
	let mut write_to = 0usize;
	for kept_line in &kept {
		let dst_start = write_to;
		let dst_end = dst_start + kept_line.length;
		if dst_start >= kept_line.offset {
			// Destination is at or past the start of the
			// source: the two ranges overlap. The destination
			// is below the source (the kept line was dropped
			// from a higher offset), so a forward copy reads
			// the source before the write touches it.
			for i in 0..kept_line.length {
				data[dst_start + i] = data[kept_line.offset + i];
			}
		} else {
			data.copy_within(
				kept_line.offset..kept_line.offset + kept_line.length,
				dst_start,
			);
		}
		write_to = dst_end;
	}
	let body_len = data.len() - header_end;
	if body_len > 0 {
		// Move the body up to follow the kept header block. The
		// source (`header_end..data.len()`) and destination
		// (`write_to..write_to + body_len`) may overlap when the
		// kept header block is shorter than the original; do the
		// copy with two disjoint mutable slices, reading from
		// `right` (the body) and writing into `left` at the new
		// offset. When the destination extends past the original
		// header end we have to push the body back to its
		// destination in two phases: the part that fits in `left`
		// goes there, the remainder goes after the original
		// header end.
		if write_to + body_len <= header_end {
			// Destination fits entirely inside the original
			// header range; one copy does it.
			let (left, right) = data.split_at_mut(header_end);
			left[write_to..write_to + body_len].copy_from_slice(right);
		} else {
			// Destination extends past the original header end.
			// Copy the first part (size `header_end - write_to`)
			// from the body's head into the tail of the kept
			// header block, then move the body's tail to its
			// final position.
			let head = header_end - write_to;
			let (left, right) = data.split_at_mut(header_end);
			left[write_to..header_end].copy_from_slice(&right[..head]);
			right.copy_within(head..body_len, 0);
		}
		write_to += body_len;
	}
	data.truncate(write_to);
}
