//! IMAP AUTHENTICATE: PLAIN and SCRAM-SHA-256 (RFC 9051, RFC 5802).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::smtp::directory::bans::BanOutcome;
use crate::smtp::scram::{ChannelBinding, ScramCredentials, ScramServer, username_of};

use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;

use super::state::State;
use super::{Output, Session};

/// In-flight SASL state between AUTHENTICATE continuation lines.
pub(super) enum PendingAuth {
	/// Tag stashed while awaiting the PLAIN response (`+ `).
	Plain { tag: String },
	/// Awaiting the SCRAM client-first message (with its channel-binding policy).
	ScramFirst {
		tag: String,
		binding: ChannelBinding,
	},
	/// Awaiting the SCRAM client-final message.
	ScramFinal {
		tag: String,
		server: Box<ScramServer>,
		credentials: Box<ScramCredentials>,
		account: String,
		/// `true` when the server-first was a ban-refusal fake: a real
		/// ban was in force at client-first, so the proof must be
		/// refused at client-final even if the ban has since
		/// expired. A banned subject who completes the exchange
		/// against a stale ban row must not be able to clear the
		/// row with a valid proof (the credentials are fake) and
		/// must not be able to extend the row with a bad one
		/// (the refusal path records no strike).
		ban_refusal: bool,
	},
	/// AUTH=LOGIN: awaiting the base64 username.
	LoginUser { tag: String },
	/// AUTH=LOGIN: awaiting the base64 password for `user`.
	LoginPass { tag: String, user: String },
	/// AUTH=EXTERNAL: awaiting the (optional) authzid.
	External { tag: String },
}

impl Session {
	/// Inject a fixed SCRAM server nonce (tests/determinism).
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

	/// The advertised SASL mechanisms, including OAuth when configured.
	pub(super) fn sasl_capability(&self) -> String {
		// Shared mechanism set: -PLUS only with a bound certificate hash, the
		// OAuth mechanisms only with a configured verifier.
		let mut caps = String::new();
		for mechanism in crate::sasl::available(
			self.client_identity.is_some(),
			self.cbind_data.is_some(),
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
	pub(super) fn capabilities(&self) -> String {
		let mut capabilities = String::from(
			"IMAP4rev1 IMAP4rev2 MOVE IDLE LITERAL+ SPECIAL-USE NAMESPACE ID UIDPLUS SORT \
THREAD=ORDEREDSUBJECT UNSELECT ENABLE ESEARCH MULTISEARCH QUOTA QUOTA=RES-STORAGE STATUS=SIZE CONDSTORE LIST-EXTENDED \
LIST-STATUS BINARY QRESYNC OBJECTID SAVEDATE PREVIEW REPLACE ACL RIGHTS=texk METADATA CHILDREN WITHIN SEARCHRES COMPRESS=DEFLATE",
		);
		// NOTIFY (RFC 5465) is only usable once authenticated; advertise it in the
		// post-authentication capability set, like other selected-state features.
		if self.account().is_some() {
			capabilities.push_str(" NOTIFY");
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

	/// The channel-binding policy for a SCRAM exchange (mirrors the SMTP side):
	/// `-PLUS` binds to the certificate hash; plain SCRAM over a bound link
	/// rejects downgrades; without a binding it is unsupported.
	fn scram_binding(&self, plus: bool) -> ChannelBinding {
		match (&self.cbind_data, plus) {
			(Some(hash), true) => ChannelBinding::Required(hash.clone()),
			(Some(_), false) => ChannelBinding::Supported,
			(None, _) => ChannelBinding::Unsupported,
		}
	}

	/// Authenticate with an OAUTHBEARER/XOAUTH2 bearer token (SASL-IR required).
	fn oauth_bearer(&mut self, tag: &str, initial: Option<String>) -> Output {
		let outcome = self
			.oauth
			.clone()
			.zip(initial)
			.and_then(|(verifier, enc)| {
				let token = parse_bearer(&enc)?;
				let email = verifier.verify(&token, unix_now())?;
				let address = Address::parse(&email).ok()?;
				match self.directory.resolve(&address) {
					Resolution::Account(account) => Some(account),
					_ => None,
				}
			})
			.and_then(|account| {
				// The bearer path bypasses `authenticate_with_ip`; the
				// per-account `allowed_protocols` check has to be issued here too,
				// with the same wire outcome as an unverifiable token.
				self.directory
					.is_protocol_allowed(&account, self.auth_protocol)
					.then_some(account)
			});
		match outcome {
			Some(account) => self.auth_success(tag, account, "AUTHENTICATE completed"),
			None => self.auth_failure(tag),
		}
	}

	/// Begin AUTHENTICATE. AUTHENTICATE requires TLS and the unauthenticated
	/// state, like LOGIN.
	pub(super) fn auth(&mut self, tag: &str, mechanism: &str, initial: Option<String>) -> Output {
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
			self.oauth.is_some(),
		) {
			return unsupported();
		}
		use crate::sasl::Mechanism;
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
			Mechanism::OauthBearer | Mechanism::Xoauth2 => self.oauth_bearer(tag, initial),
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
		let verified = decode(encoded).and_then(|pass| {
			self.directory
				.authenticate_with_ip(user, &pass, self.peer_ip, self.auth_protocol)
		});
		match verified {
			Some(account) => self.auth_success(tag, account, "AUTHENTICATE completed"),
			None => self.auth_failure(tag),
		}
	}

	/// Feed one SASL continuation line.
	pub fn auth_response(&mut self, line: &str) -> Output {
		if line == "*" {
			let tag = self.pending_auth_tag();
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
				ban_refusal,
			}) => self.scram_final(&tag, line, *server, *credentials, &account, ban_refusal),
			Some(PendingAuth::LoginUser { tag }) => self.login_user(&tag, line),
			Some(PendingAuth::LoginPass { tag, user }) => self.login_pass(&tag, &user, line),
			Some(PendingAuth::External { tag }) => self.auth_external(&tag, line),
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
		// EXTERNAL reaches the directory through resolve() — not
		// authenticate_with_ip — so the per-account `allowed_protocols`
		// check has to be issued here too. The certificate identity still
		// has to be a real local account; a mismatched protocol rejects
		// with the same wire outcome as an unknown address.
		let account = match crate::smtp::address::Address::parse(&identity) {
			Ok(address) => match self.directory.resolve(&address) {
				crate::smtp::directory::Resolution::Account(account) => account,
				_ => return self.auth_failure(tag),
			},
			Err(_) => return self.auth_failure(tag),
		};
		if !self
			.directory
			.is_protocol_allowed(&account, self.auth_protocol)
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
		let verified = crate::smtp::auth::parse_plain(encoded)
			.ok()
			.and_then(|creds| {
				self.directory.authenticate_with_ip(
					&creds.authcid,
					&creds.password,
					self.peer_ip,
					self.auth_protocol,
				)
			});
		match verified {
			Some(account) => self.auth_success(tag, account, "AUTHENTICATE completed"),
			None => self.auth_failure(tag),
		}
	}

	/// Begin SCRAM-SHA-256(-PLUS): process the optional SASL-IR client-first, or
	/// prompt for it with an empty continuation.
	fn scram_begin(&mut self, tag: &str, initial: Option<String>, plus: bool) -> Output {
		let binding = self.scram_binding(plus);
		match initial {
			Some(client_first) => self.scram_first(tag, &client_first, binding),
			None => {
				self.pending_auth = Some(PendingAuth::ScramFirst {
					tag: tag.to_string(),
					binding,
				});
				continuation("")
			}
		}
	}

	fn scram_first(&mut self, tag: &str, encoded: &str, binding: ChannelBinding) -> Output {
		let Some(client_first) = decode(encoded) else {
			// A malformed client-first (invalid base64) is a failure, but
			// the IP ban is consulted first so a banned peer cannot extend
			// its own ban by sending garbage: refused attempts never record
			// a strike. With no username there is no account row to check,
			// so the ban is the IP ban only.
			if self.is_ip_banned() {
				return self.auth_failure(tag);
			}
			self.record_scram_outcome("", None, false);
			return self.auth_failure(tag);
		};
		let Some(username) = username_of(&client_first) else {
			// A well-formed base64 client-first without a username tag is
			// still a malformed client-first. The same IP-ban-first rule
			// applies: a banned peer must not be able to extend its own
			// ban by sending repeated tag-less garbage.
			if self.is_ip_banned() {
				return self.auth_failure(tag);
			}
			self.record_scram_outcome("", None, false);
			return self.auth_failure(tag);
		};
		// Ban check before any credential lookup: an active ban on the
		// client IP or on the account short-circuits the exchange with the
		// same wire outcome as a wrong SCRAM proof (a `+` continuation
		// with a fake server-first, then NO at client-final), and the
		// SCRAM credential lookup never happens. A ban refusal is
		// distinct from a credential failure: the strike count and ban
		// expiry do not move, so the ban keeps ending when it was going
		// to end. The fake server-first keeps the refusal
		// indistinguishable from a normal exchange on the wire; the fake
		// credentials make every client proof fail the same way a wrong
		// password would.
		let resolved = match self
			.directory
			.check_ban(&username, self.peer_ip, self.auth_protocol)
		{
			BanOutcome::Banned => {
				return self.scram_ban_refusal(tag, &client_first, binding, &username);
			}
			BanOutcome::Clear { account } => account,
		};
		let mut account_for_record = resolved;
		let Some(credentials) = self.directory.scram_credentials(&username) else {
			self.record_scram_outcome(&username, account_for_record.as_deref(), false);
			return self.auth_failure(tag);
		};
		let Some((account, _)) = self.directory.credentials(&username) else {
			self.record_scram_outcome(&username, account_for_record.as_deref(), false);
			return self.auth_failure(tag);
		};
		account_for_record = Some(account.clone());
		// SCRAM bypasses authenticate_with_ip, so the per-account
		// `allowed_protocols` check has to be issued here. A restricted
		// account fails with the same wire outcome as a wrong SCRAM proof.
		if !self
			.directory
			.is_protocol_allowed(&account, self.auth_protocol)
		{
			self.record_scram_outcome(&username, account_for_record.as_deref(), false);
			return self.auth_failure(tag);
		}
		let Some(nonce) = self.fresh_nonce() else {
			// CSPRNG failure: fail closed rather than use a predictable nonce.
			self.record_scram_outcome(&username, account_for_record.as_deref(), false);
			return self.auth_failure(tag);
		};
		let mut server = ScramServer::new(nonce).with_channel_binding(binding);
		let Ok((_user, server_first)) = server.first(&client_first, &credentials) else {
			self.record_scram_outcome(&username, account_for_record.as_deref(), false);
			return self.auth_failure(tag);
		};
		self.pending_auth = Some(PendingAuth::ScramFinal {
			tag: tag.to_string(),
			server: Box::new(server),
			credentials: Box::new(credentials),
			account,
			ban_refusal: false,
		});
		continuation(&BASE64.encode(server_first))
	}

	/// A ban refusal at client-first: build a server-first from fake
	/// SCRAM credentials so the wire reply is the same `+` continuation
	/// a normal exchange produces, then stash the fake server and
	/// credentials in `pending_auth` so the client-final handler will
	/// see the proof fail exactly like a wrong password. The strike
	/// count and ban expiry stay where they were: a ban refusal is
	/// distinct from a credential failure, and no `record_ban_outcome`
	/// call follows.
	fn scram_ban_refusal(
		&mut self,
		tag: &str,
		client_first: &str,
		binding: ChannelBinding,
		username: &str,
	) -> Output {
		let Some(nonce) = self.fresh_nonce() else {
			// CSPRNG failure while building the fake server-first: the
			// no-oracle fallback is the immediate NO a malformed
			// exchange would produce. A banned subject still cannot
			// authenticate, the ban is unchanged, and the refusal
			// remains indistinguishable from a wrong-password NO.
			return self.auth_failure(tag);
		};
		let mut server = ScramServer::new(nonce).with_channel_binding(binding);
		let Ok((_user, server_first)) =
			server.first(client_first, &fake_scram_credentials_for(username))
		else {
			return self.auth_failure(tag);
		};
		self.pending_auth = Some(PendingAuth::ScramFinal {
			tag: tag.to_string(),
			server: Box::new(server),
			credentials: Box::new(fake_scram_credentials_for(username)),
			account: username.to_string(),
			ban_refusal: true,
		});
		continuation(&BASE64.encode(server_first))
	}

	fn scram_final(
		&mut self,
		tag: &str,
		encoded: &str,
		mut server: ScramServer,
		credentials: ScramCredentials,
		account: &str,
		ban_refusal: bool,
	) -> Output {
		// A ban-refusal exchange stays refused at client-final even if
		// the ban has since expired: a banned subject who started the
		// SCRAM exchange during a real ban must not be able to clear
		// the row with a valid proof (the credentials here are fake)
		// or extend the row with a bad one (no strike is recorded).
		// The recheck below catches the case where the ban fires
		// after the client-first, and the flag catches the case
		// where it expires between the two.
		if ban_refusal
			|| matches!(
				self.directory
					.check_ban(account, self.peer_ip, self.auth_protocol),
				BanOutcome::Banned
			) {
			return self.auth_failure(tag);
		}
		let Some(client_final) = decode(encoded) else {
			self.record_scram_outcome(account, Some(account), false);
			return self.auth_failure(tag);
		};
		match server.finish(&client_final, &credentials) {
			Ok(server_final) => {
				// Clear the ban store for both subjects on a successful
				// proof; the ban check at client-first already consulted
				// the same store with the same keys, so the success here
				// undoes any in-flight strikes the same way the PLAIN path
				// does.
				self.record_scram_outcome(account, Some(account), true);
				self.auth_success(
					tag,
					account.to_string(),
					&format!(
						"[SASL {}] AUTHENTICATE completed",
						BASE64.encode(server_final)
					),
				)
			}
			Err(_) => {
				self.record_scram_outcome(account, Some(account), false);
				self.auth_failure(tag)
			}
		}
	}

	fn auth_failure(&mut self, tag: &str) -> Output {
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

	/// Write the outcome of a SCRAM authentication attempt back to the
	/// shared ban store, keyed exactly as the PLAIN path keys it
	/// (`ip:<peer>` and the account the credential check resolved). A
	/// success clears both subjects; a failure records a strike against
	/// both. The ban check at the start of the exchange already decided
	/// whether to refuse the attempt; a ban refusal never reaches this
	/// helper, so the strike count and ban expiry stay where they were.
	fn record_scram_outcome(&self, login: &str, account: Option<&str>, success: bool) {
		self.directory.record_ban_outcome(
			login,
			account,
			success,
			self.peer_ip,
			self.auth_protocol,
		);
	}

	/// Whether the peer IP is currently banned. Used by the malformed
	/// client-first branches, which never see a username and so cannot
	/// consult the account ban: only the IP ban can refuse them. A
	/// banned IP must not be able to extend its own ban by sending
	/// garbage, so the branches short-circuit here before recording a
	/// strike.
	fn is_ip_banned(&self) -> bool {
		matches!(
			self.directory
				.check_ban("", self.peer_ip, self.auth_protocol),
			BanOutcome::Banned
		)
	}

	fn pending_auth_tag(&self) -> String {
		match &self.pending_auth {
			Some(
				PendingAuth::Plain { tag }
				| PendingAuth::ScramFirst { tag, .. }
				| PendingAuth::LoginUser { tag }
				| PendingAuth::External { tag },
			) => tag.clone(),
			Some(PendingAuth::ScramFinal { tag, .. } | PendingAuth::LoginPass { tag, .. }) => {
				tag.clone()
			}
			None => "*".to_string(),
		}
	}

	fn fresh_nonce(&self) -> Option<String> {
		if let Some(nonce) = &self.scram_nonce {
			return Some(nonce.clone());
		}
		use ring::rand::SecureRandom;
		let mut bytes = [0u8; 18];
		// Fail closed if the CSPRNG cannot produce a nonce.
		ring::rand::SystemRandom::new().fill(&mut bytes).ok()?;
		Some(BASE64.encode(bytes))
	}
}

/// A `+ <base64>` continuation that collects the next line as an auth response.
fn continuation(challenge_b64: &str) -> Output {
	let mut output = Output::text(format!("+ {challenge_b64}\r\n"));
	output.collect_auth = true;
	output
}

fn decode(encoded: &str) -> Option<String> {
	String::from_utf8(BASE64.decode(encoded).ok()?).ok()
}

/// SCRAM credentials used only to build a server-first message the
/// client can echo back. The `StoredKey` and `ServerKey` are all
/// zeros, so any client proof that comes back will fail the verifier
/// exactly like a wrong password, which is the point: the ban
/// refusal looks like a wrong password on the wire. The salt is
/// derived from the username (SHA-256, first 16 bytes) so the
/// server-first does not carry the tell-tale all-zero salt a banned
/// subject could use to distinguish a refusal from a real exchange.
fn fake_scram_credentials_for(username: &str) -> crate::smtp::scram::ScramCredentials {
	use ring::digest;
	let mut salt = [0u8; 16];
	let hash = digest::digest(&digest::SHA256, username.as_bytes());
	salt.copy_from_slice(&hash.as_ref()[..16]);
	crate::smtp::scram::ScramCredentials {
		salt: salt.to_vec(),
		iterations: 4096,
		stored_key: [0u8; 32],
		server_key: [0u8; 32],
	}
}

/// Extract the bearer token from a base64 OAUTHBEARER/XOAUTH2 initial response.
fn parse_bearer(encoded: &str) -> Option<String> {
	let text = decode(encoded)?;
	let token = text
		.split("auth=Bearer ")
		.nth(1)?
		.split('\x01')
		.next()?
		.trim();
	(!token.is_empty()).then(|| token.to_string())
}

fn unix_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}
