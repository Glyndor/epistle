//! Listener prerequisites and transport warnings.

use super::*;

impl Config {
	pub(super) fn validate_listeners(&self) -> Result<(), ConfigError> {
		let mut seen = HashSet::new();
		for listener in &self.listeners {
			let addr = listener.socket_addr();
			if !seen.insert(addr) {
				return Err(ConfigError::Invalid(format!(
					"duplicate listener address {addr}"
				)));
			}
			if listener.kind == crate::config::ListenerKind::Submissions && self.tls.is_none() {
				return Err(ConfigError::Invalid(format!(
					"listener {addr} is \"submissions\" (implicit TLS) but no [tls] section is configured"
				)));
			}
			// pop3s is implicit TLS by protocol definition (RFC 2595, port 995):
			// the only way to speak it is INSIDE a TLS session. Refusing here
			// surfaces the misconfiguration at validate time instead of letting
			// serve() fail at bind time with a less actionable error.
			if listener.kind == crate::config::ListenerKind::Pop3s && self.tls.is_none() {
				return Err(ConfigError::Invalid(format!(
					"listener {addr} is \"pop3s\" (implicit TLS) but no [tls] section is configured"
				)));
			}
			if listener.kind == crate::config::ListenerKind::Autoconfigs && self.tls.is_none() {
				return Err(ConfigError::Invalid(format!(
					"listener {addr} is \"autoconfigs\" (HTTPS) but no [tls] section is configured"
				)));
			}
			let needs_tls = matches!(
				listener.kind,
				crate::config::ListenerKind::Imaps
					| crate::config::ListenerKind::Imap
					| crate::config::ListenerKind::ManageSieve
			);
			if needs_tls && self.tls.is_none() {
				return Err(ConfigError::Invalid(format!(
					"listener {addr} requires a [tls] section (logins never cross plaintext)"
				)));
			}
			// Plaintext-capable listeners (Submission, WebDav, Api, Autoconfig,
			// Metrics) are accepted without [tls] so the typical "front me with
			// a TLS proxy" deployment keeps working. The loopback default is
			// the passive defense: when bound externally, warn at validate
			// time rather than reject — the next release will add an opt-in
			// flag, then fail closed by default.
			if Self::plaintext_listener_warn(listener.kind)
				&& self.tls.is_none()
				&& !addr.ip().is_loopback()
			{
				tracing::warn!(
					listener = ?listener.kind,
					addr = %addr,
					"no-TLS listener bound externally; configure [tls] or front with a TLS proxy"
				);
			}
			if listener.kind.serves_api() && self.api.is_none() {
				return Err(ConfigError::Invalid(format!(
					"listener {addr} is \"{}\" but no [api] section is configured",
					listener.kind.as_str()
				)));
			}
			if listener.kind == crate::config::ListenerKind::Oauth && !self.has_oauth_signing_key()
			{
				return Err(ConfigError::Invalid(format!(
					"listener {addr} is \"oauth\" but no [oauth] signing_key or signing_key_file \
					 is configured"
				)));
			}
		}
		self.validate_api_surfaces()
	}

	/// Whether `[oauth]` names a signing key, the one thing that mounts the
	/// OAuth routes.
	fn has_oauth_signing_key(&self) -> bool {
		self.oauth
			.as_ref()
			.is_some_and(|oauth| oauth.signing_key.is_some() || oauth.signing_key_file.is_some())
	}

	/// `[api] surfaces`: only the names of the surfaces that can be split off,
	/// each once, and none that has a listener of its own, since a surface is
	/// served in one place.
	fn validate_api_surfaces(&self) -> Result<(), ConfigError> {
		let Some(listed) = self.api.as_ref().and_then(|api| api.surfaces.as_ref()) else {
			return Ok(());
		};
		let mut seen = HashSet::new();
		for name in listed {
			let Some(surface) = crate::api::Surface::optional(name) else {
				return Err(ConfigError::Invalid(format!(
					"[api] surfaces names \"{name}\"; the names are \"jmap\", \"oauth\" and \
					 \"scim\" (management is always served by the api listener)"
				)));
			};
			if !seen.insert(surface) {
				return Err(ConfigError::Invalid(format!(
					"[api] surfaces lists \"{name}\" more than once"
				)));
			}
			if let Some(listener) = self
				.listeners
				.iter()
				.find(|listener| crate::api::Surface::of_listener(listener.kind) == Some(surface))
			{
				return Err(ConfigError::Invalid(format!(
					"[api] surfaces lists \"{name}\" and a \"{name}\" listener on {} serves it; \
					 a surface is served in one place",
					listener.socket_addr()
				)));
			}
		}
		Ok(())
	}
}
