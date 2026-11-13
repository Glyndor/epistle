//! The OAuth ES256 key-pair decision the plan and the apply phase share.

use super::super::ApplyError;

/// What the apply phase will do for the OAuth ES256 key pair. `private_reused`
/// is `true` when the apply phase will leave the private key on disk
/// untouched; `public_reused` is `true` when the apply phase will leave the
/// public key on disk untouched. The plan and the apply phase both call
/// this function so the two agree on whether each half is reused.
pub(super) struct OAuthPairDecision {
	/// `true` when the apply phase will reuse the existing private key.
	pub(super) private_reused: bool,
	/// `true` when the apply phase will reuse the existing public key.
	pub(super) public_reused: bool,
}

/// Resolve the OAuth pair-state decision shared by plan and apply. Returns
/// `Err` when only the public half exists (the apply phase refuses to mint a
/// fresh unrelated private key) or when both halves exist but do not
/// correspond. The plan surfaces these as errors so the operator sees the
/// refusal before confirming.
pub(super) fn resolve_oauth_pair(
	private_exists: bool,
	public_exists: bool,
	private_path: &std::path::Path,
	public_path: &std::path::Path,
) -> Result<OAuthPairDecision, ApplyError> {
	match (private_exists, public_exists) {
		(true, true) => {
			// Both halves exist; the apply phase verifies they
			// correspond before reusing. The plan cannot fail here
			// unless the on-disk bytes decode to something that is
			// not a P-256 PKCS#8 key; a corrupt file is reported as
			// `OAuthPairIncomplete` so the operator sees the same
			// shape of error whether they hit it in `plan` or
			// `apply`.
			let private_bytes = crate::cli::regular::read::read(private_path)
				.map_err(|error| ApplyError::KeyWrite(private_path.to_path_buf(), error))?;
			let private_text = std::str::from_utf8(&private_bytes).map_err(|_| {
				ApplyError::OAuthPairIncomplete(format!(
					"oauth private key {} is not valid utf-8; cannot derive the public key",
					private_path.display()
				))
			})?;
			let derived = crate::cli::util::derive_oauth_public_from_private(private_text)
				.ok_or_else(|| {
					ApplyError::OAuthPairIncomplete(format!(
						"oauth private key {} is not a valid PKCS#8 ES256 key; cannot derive the public key",
						private_path.display()
					))
				})?;
			let public_bytes = crate::cli::regular::read::read(public_path)
				.map_err(|error| ApplyError::KeyWrite(public_path.to_path_buf(), error))?;
			let public_text = std::str::from_utf8(&public_bytes).map_err(|_| {
				ApplyError::OAuthPairIncomplete(format!(
					"oauth public key {} is not valid utf-8",
					public_path.display()
				))
			})?;
			if public_text.trim() != derived.trim() {
				return Err(ApplyError::OAuthPairMismatch);
			}
			Ok(OAuthPairDecision {
				private_reused: true,
				public_reused: true,
			})
		}
		(true, false) => {
			// The apply phase derives the public from the private
			// and writes it. The plan says private is reused, public
			// is not (the apply phase writes it).
			Ok(OAuthPairDecision {
				private_reused: true,
				public_reused: false,
			})
		}
		(false, true) => Err(ApplyError::OAuthPairIncomplete(format!(
			"oauth public key {} exists but the matching private key {} is missing; restore the private key from backup or delete {} and rerun init",
			public_path.display(),
			private_path.display(),
			public_path.display()
		))),
		(false, false) => Ok(OAuthPairDecision {
			private_reused: false,
			public_reused: false,
		}),
	}
}
