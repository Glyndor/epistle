//! The closing marker that tells a complete pg_dump from a cut one.

/// True when `stdout` ends with the closing marker of a complete pg_dump.
/// pg_dump closes with `-- PostgreSQL database dump complete`, then a bare
/// `--` line and, since the releases of August 2025, a `\unrestrict <key>`
/// line. Only the marker followed by those lines (and blank ones) counts;
/// anything else after it, or no marker in the tail, is a cut dump.
pub(in crate::cli::backup) fn output_ends_with_pg_dump_complete(stdout: &[u8]) -> bool {
	const MARKER: &str = "-- PostgreSQL database dump complete";
	const WINDOW: usize = 1024;
	let tail = &stdout[stdout.len().saturating_sub(WINDOW)..];
	let tail = String::from_utf8_lossy(tail);
	let Some(at) = tail.rfind(MARKER) else {
		return false;
	};
	if !tail[..at].is_empty() && !tail[..at].ends_with('\n') {
		return false;
	}
	let mut rest = tail[at + MARKER.len()..].lines();
	rest.next().is_none_or(|same_line| same_line.is_empty())
		&& rest.all(|line| {
			let line = line.trim_end();
			line.is_empty() || line == "--" || line.starts_with("\\unrestrict ")
		})
}
