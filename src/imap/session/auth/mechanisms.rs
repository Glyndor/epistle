//! IMAP AUTHENTICATE: the shared SASL machinery and the password
//! mechanisms (RFC 9051). SCRAM-SHA-256 lives in [`super::scram`] and the
//! bearer-token mechanisms in [`super::oauth`].

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::smtp::directory::Proof;
use crate::smtp::directory::hash_gate::Verdict;

use super::super::super::command::Secret;
use super::super::state::State;
use super::super::{Output, Session};
use super::PendingAuth;

impl Session {
	/// Inject a fixed SCRAM server nonce, so tests are deterministic.
	pub fn with_scram_nonce(mut self, nonce: &str) -> Self {
		self.scram_nonce = Some(nonce.to_string());
		self
	}

	/// Attach an OAuth token verifier (enables OAUTHBEARER/XOAUTH2).
	pub fn with_oauth(
		mut self,
		verifier: Option<std::sync::Arc<crate::oauth::OauthVerifier>>,
	) -> Self {
		self.oauth = verifier;
		self
	}

	/// Toggle the `[auth] scram` knob for this listener. `true` keeps the
	/// default behaviour (both SCRAM-SHA-256 and `-PLUS` advertised when
	/// channel binding is available); `false` hides both on the wire and
	/// refuses an explicit `AUTHENTICATE` against them.
	pub fn with_scram_enabled(mut self, enabled: bool) -> Self {
		self.scram_enabled = enabled;
		self
	}

	/// The advertised SASL mechanisms, including OAuth when configured.
	pub(in crate::imap::session) fn sasl_capability(&self) -> String {
		// Shared mechanism set: -PLUS only with a bound certificate hash, the
		// OAuth mechanisms only with a configured verifier.
		let mut caps = String::new();
		for mechanism in crate::sasl::available(
			self.client_identity.is_some(),
			self.cbind_data.is_some(),
			self.scram_enabled,
			self.oauth.is_some(),
		) {
			caps.push_str(" AUTH=");
			caps.push_str(mechanism.name());
		}
		caps.push_str(" SASL-IR");
		caps
	}

	/// The advertised IMAP capabilities, including SASL mechanisms and the
	/// STARTTLS/LOGINDISABLED state.
	pub(in crate::imap::session) fn capabilities(&self) -> String {
		// APPENDLIMIT (RFC 7889 §3) carries the number because the limit is
		// the same for every mailbox: it is the per-listener APPENDLIMIT
		// the parser and the network layer enforce.
		let append_limit = self.append_limit;
		let mut capabilities = format!(
			"IMAP4rev1 IMAP4rev2 MOVE IDLE LITERAL+ SPECIAL-USE NAMESPACE ID UIDPLUS SORT \
THREAD=ORDEREDSUBJECT THREAD=REFERENCES APPENDLIMIT={append_limit} UNSELECT ENABLE ESEARCH \
MULTISEARCH QUOTA QUOTA=RES-STORAGE STATUS=SIZE CONDSTORE LIST-EXTENDED LIST-STATUS BINARY \
QRESYNC OBJECTID SAVEDATE PREVIEW REPLACE ACL RIGHTS=texk METADATA CHILDREN WITHIN SEARCHRES \
COMPRESS=DEFLATE",
		);
		// NOTIFY (RFC 5465) is only usable once authenticated; advertise it in the
		// post-authentication capability set, like other selected-state features.
		// UIDONLY (RFC 9586) and UTF8=ACCEPT (RFC 6855) are turned on with
		// ENABLE, which needs a login too.
		if self.account().is_some() {
			capabilities.push_str(" NOTIFY UIDONLY UTF8=ACCEPT");
		}
		if self.tls_available {
			capabilities.push_str(" STARTTLS");
		}
		if self.tls_active {
			capabilities.push_str(&self.sasl_capability());
		} else {
			capabilities.push_str(" LOGINDISABLED");
		}
		capabilities
	}

	/// Begin AUTHENTICATE. AUTHENTICATE requires TLS and the unauthenticated
	/// state, like LOGIN.
	pub(in crate::imap::session) fn auth(
		&mut self,
		tag: &str,
		mechanism: &str,
		initial: Option<Secret>,
	) -> Output {
		if !self.tls_active {
			return Output::text(format!("{tag} NO [PRIVACYREQUIRED] STARTTLS first\r\n"));
		}
		if !matches!(self.state, State::NotAuthenticated { .. }) {
			return Output::text(format!("{tag} BAD already authenticated\r\n"));
		}
		// Only negotiate a mechanism that is currently advertised (channel
		// binding present for -PLUS, a verifier present for the OAuth ones).
		let unsupported = || Output::text(format!("{tag} NO unsupported SASL mechanism\r\n"));
		let Some(parsed) = crate::sasl::Mechanism::parse(mechanism) else {
			return unsupported();
		};
		if !crate::sasl::is_available(
			parsed,
			self.client_identity.is_some(),
			self.cbind_data.is_some(),
			self.scram_enabled,
			self.oauth.is_some(),
		) {
			return unsupported();
		}
		use crate::sasl::Mechanism;
		let initial = initial.as_ref().map(|secret| secret.expose().to_string());
		match parsed {
			Mechanism::External => match initial {
				Some(response) => self.auth_external(tag, &response),
				None => {
					self.pending_auth = Some(PendingAuth::External {
						tag: tag.to_string(),
					});
					continuation("")
				}
			},
			Mechanism::Plain => match initial {
				Some(response) => self.auth_plain(tag, &response),
				None => {
					self.pending_auth = Some(PendingAuth::Plain {
						tag: tag.to_string(),
					});
					continuation("")
				}
			},
			Mechanism::ScramSha256 => self.scram_begin(tag, initial, false),
			Mechanism::ScramSha256Plus => self.scram_begin(tag, initial, true),
			Mechanism::Login => match initial {
				// SASL-IR initial response is the username.
				Some(user) => self.login_user(tag, &user),
				None => {
					self.pending_auth = Some(PendingAuth::LoginUser {
						tag: tag.to_string(),
					});
					continuation("VXNlcm5hbWU6")
				}
			},
			Mechanism::OauthBearer | Mechanism::Xoauth2 => self.oauth_begin(tag, initial),
		}
	}

	/// AUTH=LOGIN: record the username and prompt for the password.
	fn login_user(&mut self, tag: &str, encoded: &str) -> Output {
		let Some(user) = decode(encoded) else {
			return self.auth_failure(tag);
		};
		self.pending_auth = Some(PendingAuth::LoginPass {
			tag: tag.to_string(),
			user,
		});
		continuation("UGFzc3dvcmQ6")
	}

	/// AUTH=LOGIN: verify the password (plus any TOTP, or an app password whose
	/// CIDR allowlist matches the peer IP) against the username.
	fn login_pass(&mut self, tag: &str, user: &str, encoded: &str) -> Output {
		let verdict = match decode(encoded) {
			Some(pass) => {
				self.directory
					.authenticate_verdict(user, &pass, self.peer_ip, self.auth_protocol)
			}
			None => Verdict::Refused,
		};
		self.password_verdict(tag, verdict)
	}

	/// Feed one SASL continuation line.
	pub fn auth_response(&mut self, line: &str) -> Output {
		if line == "*" {
			let tag = self.pending_auth_tag();
			// Cancelling after the error challenge is still the failed
			// attempt it acknowledges, so it cannot be used to skip the count.
			if matches!(self.pending_auth, Some(PendingAuth::BearerError { .. })) {
				return self.auth_failure(&tag);
			}
			self.pending_auth = None;
			return Output::text(format!("{tag} BAD authentication cancelled\r\n"));
		}
		match self.pending_auth.take() {
			Some(PendingAuth::Plain { tag }) => self.auth_plain(&tag, line),
			Some(PendingAuth::ScramFirst { tag, binding }) => self.scram_first(&tag, line, binding),
			Some(PendingAuth::ScramFinal {
				tag,
				server,
				credentials,
				account,
				refusal,
			}) => self.scram_final(&tag, line, *server, *credentials, &account, refusal),
			Some(PendingAuth::LoginUser { tag }) => self.login_user(&tag, line),
			Some(PendingAuth::LoginPass { tag, user }) => self.login_pass(&tag, &user, line),
			Some(PendingAuth::External { tag }) => self.auth_external(&tag, line),
			Some(PendingAuth::Bearer { tag }) => self.oauth_bearer(&tag, Some(line.to_string())),
			Some(PendingAuth::BearerError { tag }) => self.auth_failure(&tag),
			None => Output::text("* BAD unexpected authentication response\r\n".to_string()),
		}
	}

	/// SASL EXTERNAL: authenticate as the identity in the verified client
	/// certificate. The optional authzid (base64, or `=`/empty) must be empty or
	/// equal the certificate identity — no acting as another user.
	fn auth_external(&mut self, tag: &str, encoded: &str) -> Output {
		let Some(identity) = self.client_identity.clone() else {
			return self.auth_failure(tag);
		};
		let trimmed = encoded.trim();
		let authzid = if trimmed.is_empty() || trimmed == "=" {
			String::new()
		} else {
			match BASE64.decode(trimmed) {
				Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
				Err(_) => return self.auth_failure(tag),
			}
		};
		if !authzid.is_empty() && authzid != identity {
			return self.auth_failure(tag);
		}
		// EXTERNAL reaches the directory through resolve(), not
		// authenticate_with_ip, so the account rules (disabled, protocol
		// allowlist) have to be asked for here. The certificate identity
		// still has to be a real local account; a refusal rejects with the
		// same wire outcome as an unknown address.
		let account = match crate::smtp::address::Address::parse(&identity) {
			Ok(address) => match self.directory.resolve_exact(&address) {
				Some(account) => account,
				None => return self.auth_failure(tag),
			},
			Err(_) => return self.auth_failure(tag),
		};
		if !self
			.directory
			.admit_login(&account, self.auth_protocol, Proof::Federated)
		{
			return self.auth_failure(tag);
		}
		self.auth_success(tag, account, "AUTHENTICATE completed")
	}

	fn auth_plain(&mut self, tag: &str, encoded: &str) -> Output {
		// Route through the directory so the primary password (with any TOTP) and
		// app passwords (CIDR-checked against the peer IP) are both accepted; no
		// oracle (unknown user behaves like a wrong password). The protocol tag
		// is the listener kind this session serves (Imap or Imaps) so a
		// per-account `allowed_protocols` that does not include it rejects
		// exactly like an unknown login.
		let verdict = match crate::smtp::auth::parse_plain(encoded) {
			Ok(creds) => self.directory.authenticate_verdict(
				&creds.authcid,
				&creds.password,
				self.peer_ip,
				self.auth_protocol,
			),
			Err(_) => Verdict::Refused,
		};
		self.password_verdict(tag, verdict)
	}

	/// End a password AUTHENTICATE: success, a refusal counted as a failed
	/// attempt, or the temporary failure of a full password-check gate, which
	/// is neither a wrong credential nor counted as one.
	fn password_verdict(&mut self, tag: &str, verdict: Verdict) -> Output {
		match verdict {
			Verdict::Admitted { account, .. } => {
				self.auth_success(tag, account, "AUTHENTICATE completed")
			}
			Verdict::Refused => self.auth_failure(tag),
			Verdict::Busy => {
				self.pending_auth = None;
				Output::text(format!("{tag} NO [UNAVAILABLE] Try again later\r\n"))
			}
		}
	}

	pub(in crate::imap::session) fn auth_failure(&mut self, tag: &str) -> Output {
		self.pending_auth = None;
		if let State::NotAuthenticated { login_failures } = &mut self.state {
			*login_failures += 1;
			if *login_failures >= 3 {
				return Output::closing(format!(
					"* BYE too many failures\r\n{tag} NO authentication failed\r\n"
				));
			}
		}
		Output::text(format!("{tag} NO authentication failed\r\n"))
	}

	fn pending_auth_tag(&self) -> String {
		match &self.pending_auth {
			Some(
				PendingAuth::Plain { tag }
				| PendingAuth::ScramFirst { tag, .. }
				| PendingAuth::LoginUser { tag }
				| PendingAuth::External { tag }
				| PendingAuth::Bearer { tag }
				| PendingAuth::BearerError { tag },
			) => tag.clone(),
			Some(PendingAuth::ScramFinal { tag, .. } | PendingAuth::LoginPass { tag, .. }) => {
				tag.clone()
			}
			None => "*".to_string(),
		}
	}
}

/// A `+ <base64>` continuation that collects the next line as an auth response.
pub(in crate::imap::session) fn continuation(challenge_b64: &str) -> Output {
	let mut output = Output::text(format!("+ {challenge_b64}\r\n"));
	output.collect_auth = true;
	output
}

pub(in crate::imap::session) fn decode(encoded: &str) -> Option<String> {
	String::from_utf8(BASE64.decode(encoded).ok()?).ok()
}
