//! One process invocation kept as plain data, so the tests can read what would
//! run without spawning it.

/// A process invocation as a list of arguments and environment additions.
/// Kept as plain data so the tests can inspect what would be run without
/// spawning anything. Host passwords live in `env`; container passwords
/// are loaded by the container shell and never reach the host process.
/// `argv` is what the kernel would publish through `/proc/<pid>/cmdline`,
/// so a test that walks `argv` and finds the secret anywhere there is a
/// regression we want to catch.
#[derive(Clone, PartialEq, Eq)]
pub struct CommandSpec {
	argv: Vec<String>,
	env: Vec<(String, String)>,
	stdin_payload: Option<Vec<u8>>,
}

impl std::fmt::Debug for CommandSpec {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let env: Vec<_> = self
			.env
			.iter()
			.map(|(key, _)| (key, "<redacted>"))
			.collect();
		f.debug_struct("CommandSpec")
			.field("argv", &self.argv)
			.field("env", &env)
			.field("stdin_len", &self.stdin_payload.as_ref().map(Vec::len))
			.finish()
	}
}

impl CommandSpec {
	pub(super) fn new(argv: Vec<String>) -> Self {
		Self {
			argv,
			env: Vec::new(),
			stdin_payload: None,
		}
	}

	pub(super) fn with_env(mut self, key: &str, value: &str) -> Self {
		self.env.push((key.to_string(), value.to_string()));
		self
	}

	pub(super) fn with_stdin(mut self, payload: Vec<u8>) -> Self {
		self.stdin_payload = Some(payload);
		self
	}

	/// The argv the kernel would publish through `/proc/<pid>/cmdline`. The
	/// test on the password-leak path walks this slice; the runtime path
	/// hands it to `Command::new(argv[0]).args(&argv[1..])`.
	pub(in crate::cli::backup) fn argv(&self) -> &[String] {
		&self.argv
	}

	/// The environment additions the spec applies to the inherited
	/// environment. Inherited values are passed through; only the
	/// additions in this list are guaranteed visible.
	pub(in crate::cli::backup) fn env(&self) -> &[(String, String)] {
		&self.env
	}

	/// The bytes piped to the child's stdin when the spec is run, if any.
	pub(in crate::cli::backup) fn stdin_payload(&self) -> Option<&[u8]> {
		self.stdin_payload.as_deref()
	}
}
