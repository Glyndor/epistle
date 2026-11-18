use std::path::Path;

/// A provider API token scoped to a single DNS zone (least privilege). Loaded
/// from an environment variable or a `0600` file; redacted in `Debug` and never
/// logged.
#[derive(Clone)]
pub struct ScopedSecret {
	zone: String,
	token: String,
}

impl ScopedSecret {
	/// A secret for `zone` with an explicit `token`.
	pub fn new(zone: impl Into<String>, token: impl Into<String>) -> Self {
		ScopedSecret {
			zone: zone.into(),
			token: token.into(),
		}
	}

	/// Read the token for `zone` from environment variable `var`. Returns
	/// `None` when the variable is unset or empty.
	pub fn from_env(zone: impl Into<String>, var: &str) -> Option<Self> {
		let token = std::env::var(var).ok()?;
		let token = token.trim();
		(!token.is_empty()).then(|| ScopedSecret::new(zone, token))
	}

	/// Read the token for `zone` from a file that must not be group/world
	/// accessible (`0600`/`0400`), failing closed otherwise.
	pub fn from_file(zone: impl Into<String>, path: &Path) -> std::io::Result<Self> {
		ensure_private(path)?;
		let token = std::fs::read_to_string(path)?.trim().to_string();
		if token.is_empty() {
			return Err(std::io::Error::other("secret file is empty"));
		}
		Ok(ScopedSecret::new(zone, token))
	}

	/// The zone this secret is scoped to.
	pub fn zone(&self) -> &str {
		&self.zone
	}

	/// The token (handle with care; never log it).
	pub fn token(&self) -> &str {
		&self.token
	}

	/// Whether this secret authorizes operating on `name` — only its own zone
	/// or a name within it, never another zone (least privilege).
	pub fn authorizes(&self, name: &str) -> bool {
		let name = name.to_ascii_lowercase();
		let zone = self.zone.to_ascii_lowercase();
		name == zone || name.ends_with(&format!(".{zone}"))
	}
}

impl std::fmt::Debug for ScopedSecret {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ScopedSecret")
			.field("zone", &self.zone)
			.field("token", &"***")
			.finish()
	}
}

/// Fail unless `path` is readable only by its owner (no group/world bits).
#[cfg(unix)]
fn ensure_private(path: &Path) -> std::io::Result<()> {
	use std::os::unix::fs::PermissionsExt;
	let mode = std::fs::metadata(path)?.permissions().mode();
	if mode & 0o077 != 0 {
		return Err(std::io::Error::other(format!(
			"secret file {} is group/world-accessible (mode {:#o}); restrict it to 0600",
			path.display(),
			mode & 0o777
		)));
	}
	Ok(())
}

#[cfg(not(unix))]
fn ensure_private(_path: &Path) -> std::io::Result<()> {
	Ok(())
}
