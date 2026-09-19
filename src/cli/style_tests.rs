//! `Progress` and `warn_to` against a buffer: what reaches the sink off a
//! terminal, what reaches it on one, and where the 100 ms throttle cuts.

use super::*;

/// The exact bytes `finish` writes before the summary on a terminal.
const CLEAR: &str = "\r\x1b[2K\r";

#[test]
fn off_terminal_three_ticks_write_nothing_and_finish_writes_only_the_summary() {
	let mut sink = Vec::new();
	let base = Instant::now();
	let mut progress = Progress::with_sink("importing", &mut sink, false);
	progress.tick_at(1, base);
	progress.tick_at(2, base + Duration::from_millis(50));
	progress.tick_at(3, base + Duration::from_millis(150));
	progress.finish("done 3");
	assert_eq!(sink, b"done 3\n");
}

#[test]
fn on_terminal_first_tick_draws_then_throttle_holds_then_next_past_100ms_draws() {
	let mut sink = Vec::new();
	let base = Instant::now();
	let mut progress = Progress::with_sink("importing", &mut sink, true);
	// First tick always draws.
	progress.tick_at(1, base);
	// 50 ms after the last draw: inside the throttle, dropped.
	progress.tick_at(2, base + Duration::from_millis(50));
	// 150 ms after the last draw: drawn.
	progress.tick_at(3, base + Duration::from_millis(150));
	progress.finish("done");
	assert_eq!(sink, b"\rimporting 1\rimporting 3\r\x1b[2K\rdone\n");
}

/// The throttle is measured from the last tick that drew, and its edge is
/// exact: 99 ms is dropped, 100 ms draws.
#[test]
fn throttle_edge_is_one_hundred_milliseconds_from_the_last_draw() {
	let mut sink = Vec::new();
	let base = Instant::now();
	let mut progress = Progress::with_sink("checking", &mut sink, true);
	progress.tick_at(1, base);
	progress.tick_at(2, base + Duration::from_millis(99));
	progress.tick_at(3, base + Duration::from_millis(100));
	// 199 ms from `base` is 99 ms from the draw at 100 ms: dropped. Measured
	// from the dropped tick at 99 ms it would have been 100 ms and drawn.
	progress.tick_at(4, base + Duration::from_millis(199));
	progress.finish("done");
	assert_eq!(
		String::from_utf8_lossy(&sink),
		format!("\rchecking 1\rchecking 3{CLEAR}done\n")
	);
}

#[test]
fn warn_to_writes_warning_prefix_then_the_message_into_a_buffer() {
	// The sink is wrapped in `anstream::AutoStream::new(_, Auto)`: the wrapper
	// decides to strip the prefix codes because the underlying writer is not a
	// terminal, so the buffer ends up with plain text the operator can grep.
	let mut sink = Vec::new();
	let mut stream = anstream::AutoStream::new(&mut sink, anstream::ColorChoice::Auto);
	warn_to(&mut stream, "hello");
	assert_eq!(sink, b"warning: hello\n");
}

#[test]
fn error_to_writes_error_prefix_then_the_message_into_a_buffer() {
	let mut sink = Vec::new();
	let mut stream = anstream::AutoStream::new(&mut sink, anstream::ColorChoice::Auto);
	error_to(&mut stream, "hello");
	assert_eq!(sink, b"error: hello\n");
}

#[test]
fn warn_to_keeps_the_codes_when_the_wrapper_is_a_terminal() {
	// The same prefix bytes, written into a wrapper that reports itself as a
	// terminal: the codes must reach the sink verbatim. We model the
	// "terminal" case by handing `anstream` `AlwaysAnsi`, which is what the
	// production wrapper does when stderr is a TTY.
	let mut sink = Vec::new();
	let mut stream = anstream::AutoStream::new(&mut sink, anstream::ColorChoice::AlwaysAnsi);
	warn_to(&mut stream, "hello");
	assert_eq!(
		String::from_utf8_lossy(&sink),
		"\x1b[1m\x1b[33mwarning:\x1b[0m hello\n"
	);
}
