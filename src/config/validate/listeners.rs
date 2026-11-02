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
			if listener.kind == crate::config::ListenerKind::Api && self.api.is_none() {
				return Err(ConfigError::Invalid(format!(
					"listener {addr} is \"api\" but no [api] section is configured"
				)));
			}
		}
		Ok(())
	}
}
