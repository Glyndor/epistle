//! The mailbox adapter: the IMAP command line a client sends.

/// IMAP command line: the literal announcement the connection loop reads
/// before anything else, then the command parser.
pub fn imap_command_line(line: &str) {
	if let Some(literal) = crate::imap::command::literal_announcement_in_line(line) {
		std::hint::black_box(literal.size);
	}
	let _ = crate::imap::command::parse(line, crate::imap::command::DEFAULT_APPEND_LIMIT);
}
