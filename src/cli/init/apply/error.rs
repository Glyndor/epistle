//! The errors the apply phase can produce, each carrying its own diagnostic.

use std::path::PathBuf;

/// Errors the apply phase can produce. Each variant owns its own
/// diagnostic so callers can route it through `style::error` without an
/// intermediate formatting step (and so a taint analyser cannot read a
/// constant string into a key sink).
#[derive(Debug)]
pub enum ApplyError {
	/// The database volume exists without credentials, or its state cannot be checked.
	DatabaseVolume(String),
	/// The first account or its role aliases could not be created after
	/// the configuration was written. Carries the reason.
	FirstAccount(String),
	/// The data directory could not be created or its `keys/` child
	/// could not be created with mode `0700`.
	KeysDir(PathBuf, std::io::Error),
	/// Writing a secret file (DKIM, storage, OAuth, TLS, self-signed
	/// cert) to disk failed. Distinct from `ConfigWrite` so the
	/// operator-facing message names the secret file and the operator
	/// can recover or rotate that credential.
	KeyWrite(PathBuf, std::io::Error),
	/// The OAuth ES256 key pair is incomplete: only the public half
	/// is on disk and the matching private half is missing. Carries
	/// the operator-facing recovery message (which missing file to
	/// restore or to delete). The apply phase refuses to mint a fresh
	/// unrelated private key because doing so would silently break
	/// every existing token issuer that pins the old public key.
	OAuthPairIncomplete(String),
	/// The OAuth ES256 key pair is present but the two halves do not
	/// correspond: the public point on disk is not derivable from the
	/// private key on disk. Tokens signed with the private key would
	/// not verify against the public one.
	OAuthPairMismatch,
	/// The self-signed certificate pair is incomplete: only the
	/// certificate half is on disk and the matching private key is
	/// missing. The apply phase refuses to mint a fresh key because
	/// doing so would silently break any operator who pinned the old
	/// key in their ACME configuration or backup. Carries the
	/// operator-facing recovery message.
	CertPairIncomplete(String),
	/// Building the desired config from the answers failed (TOML encode).
	ConfigEncode(String),
	/// The candidate config failed to validate through `Config::load`;
	/// the destination was never touched. Carries the formatted
	/// `ConfigError`.
	ConfigInvalid(String),
	/// Reading or rewriting the existing config file failed.
	ConfigRead(PathBuf, std::io::Error),
	/// Writing the new config file through `write_secret` failed.
	ConfigWrite(PathBuf, std::io::Error),
	/// Creating the parent directory of `config_path` failed. Distinct
	/// from `ConfigWrite` so the operator-facing message names the
	/// directory, not the config file.
	ConfigDir(PathBuf, std::io::Error),
	/// `config_path` is a symlink. The apply phase refuses rather than
	/// silently replace the link with a regular file; the operator
	/// has to resolve the link by hand first.
	ConfigSymlink(PathBuf),
	/// `config_path` exists and is not a regular file (a directory,
	/// a fifo, a device, or a socket). The apply phase refuses
	/// rather than silently overwrite or step into a non-file; the
	/// operator has to point `config_path` at a file.
	ConfigNotAFile(PathBuf),
	/// The RSA DKIM key could not be produced (the in-process generator
	/// failed: no entropy, a rejected key). Carries the operator-facing
	/// reason. Distinct from `KeyWrite` because no key file was
	/// attempted; the failure is in the key-generation step itself,
	/// before any write would have happened.
	RsaKeygen(String),
	/// The system CSPRNG could not produce bytes for a key (DKIM
	/// ed25519, certificate pair, storage, oauth). Carries the
	/// failing source so the operator can see which key did not
	/// land. The previous shape `expect`-panicked on the same
	/// condition and exited 101 with no report; the run now exits
	/// 1 with the report of what already landed.
	Rng(String),
	/// An existing secret file (today: the database password)
	/// is on disk but cannot be read, a directory in its place,
	/// a `mode 0o000` file, an unreadable mount. The apply phase
	/// refuses to mint a fresh value because PostgreSQL still
	/// holds the old credential in its volume and a new password
	/// would lock epistle out. The error names the path and the
	/// underlying cause so the operator can repair the file's
	/// mode (or remove it by hand) and rerun.
	ExistingSecretUnreadable(PathBuf, std::io::Error),
	/// The answers leave the mail image unset (the default
	/// host-binary shape), but the host binary the compose
	/// file bind-mounts is missing or is not a statically linked
	/// 64-bit LE ELF. The apply phase refuses rather than emit
	/// a compose file the runtime cannot serve: a broken mail
	/// service is worse than a refused `init`. The message names
	/// the failing reason and what the operator needs to do
	/// (install the .deb, or set `image` in the answers).
	HostBinaryInvalid(String),
	/// A key under data_dir could not be moved to the directory beside it.
	KeyMove(String),
	/// The `--answers` file is a symlink, is not a regular file, or holds a
	/// credential while group or others can read it.
	AnswersFile(PathBuf, String),
	/// An API key labelled `panel` exists with a reach other than the
	/// panel's, so its secret is not replaced. Carries the operator-facing
	/// message, which names the settings and never a secret.
	PanelKey(String),
}

impl std::fmt::Display for ApplyError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ApplyError::DatabaseVolume(message) | ApplyError::PanelKey(message) => {
				f.write_str(message)
			}
			ApplyError::FirstAccount(why) => write!(f, "first account: {why}"),
			ApplyError::KeysDir(path, error) => write!(
				f,
				"cannot create keys directory {}: {error}",
				path.display()
			),
			ApplyError::KeyWrite(path, error) => {
				write!(f, "cannot write key file {}: {error}", path.display())
			}
			ApplyError::OAuthPairIncomplete(message) => write!(f, "{message}"),
			ApplyError::OAuthPairMismatch => write!(
				f,
				"oauth public and private keys do not correspond; restore the matching half from backup or delete both and rerun init"
			),
			ApplyError::CertPairIncomplete(message) => write!(f, "{message}"),
			ApplyError::ConfigEncode(message) => {
				write!(f, "cannot encode the desired config: {message}")
			}
			ApplyError::ConfigInvalid(message) => {
				write!(f, "the candidate config is invalid: {message}")
			}
			ApplyError::AnswersFile(path, why) => {
				write!(f, "answers file {} {why}", path.display())
			}
			ApplyError::ConfigRead(path, error) => {
				write!(f, "cannot read existing config {}: {error}", path.display())
			}
			ApplyError::ConfigWrite(path, error) => {
				write!(f, "cannot write config {}: {error}", path.display())
			}
			ApplyError::ConfigDir(path, error) => write!(
				f,
				"cannot create config directory {}: {error}",
				path.display()
			),
			ApplyError::ConfigSymlink(path) => write!(
				f,
				"config_path {} is a symlink; resolve the link (or replace it with its target) and rerun init",
				path.display()
			),
			ApplyError::ConfigNotAFile(path) => write!(
				f,
				"config_path {} exists but is not a regular file; point config_path at a file and rerun init",
				path.display()
			),
			ApplyError::RsaKeygen(reason) => {
				write!(f, "cannot generate the RSA DKIM key: {reason}")
			}
			ApplyError::Rng(source) => {
				write!(f, "system CSPRNG could not produce bytes for {source}")
			}
			ApplyError::ExistingSecretUnreadable(path, error) => write!(
				f,
				"the existing secret at {} cannot be read ({error}); \
				 not replaced to avoid locking the database out, \
				 restore read access (or remove the file by hand) and rerun init",
				path.display()
			),
			ApplyError::HostBinaryInvalid(message) => f.write_str(message),
			ApplyError::KeyMove(message) => f.write_str(message),
		}
	}
}

impl std::error::Error for ApplyError {}
