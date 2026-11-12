//! Reading one value from standard input.

/// The stdin read failed. The reason has already been written to stderr, so a
/// caller only has to choose its exit code.
///
/// Carries no data on purpose. `read_line` feeds values that callers bind to
/// names like `token` and `password`, which makes every constant returned from
/// it look, to a taint analyser, like a credential travelling to a credential
/// sink - `rust/hard-coded-cryptographic-value` flagged the exit code on the
/// error path for exactly that reason. Keeping the exit code at the call site
/// leaves nothing constant flowing out of this function.
pub(in crate::cli) struct InputError;

/// Read one non-empty line (CR-trimmed) from `reader`.
///
/// Diagnostics go to stderr; the caller turns [`InputError`] into an exit code.
pub(in crate::cli) fn read_line(reader: impl std::io::BufRead) -> Result<String, InputError> {
	let value = match reader.lines().next() {
		Some(Ok(line)) => line.trim_end_matches('\r').to_owned(),
		Some(Err(error)) => {
			crate::cli::style::error(format_args!("reading stdin: {error}"));
			return Err(InputError);
		}
		None => {
			crate::cli::style::error("no input: pipe or type the value on stdin");
			return Err(InputError);
		}
	};
	if value.is_empty() {
		crate::cli::style::error("input must not be empty");
		return Err(InputError);
	}
	Ok(value)
}
