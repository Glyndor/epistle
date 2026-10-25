//! IMAP AUTHENTICATE: PLAIN and SCRAM-SHA-256 (RFC 9051, RFC 5802).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::smtp::directory::bans::BanOutcome;
use crate::smtp::directory::hash_gate::Verdict;
use crate::smtp::directory::{Proof, ScramPlan, ScramRefusal};
use crate::smtp::scram::{ChannelBinding, ScramCredentials, ScramServer, username_of};

use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;

use super::super::command::Secret;
use super::state::State;
use super::{Output, Session};
use crate::smtp::directory::bearer_proof;

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
		/// `Some` when the server-first was built on decoy credentials: the
		/// exchange cannot succeed, and the refusal says whether it still
		/// counts as a failed attempt (see [`ScramRefusal`]). A banned
		/// subject who completes the exchange must not clear the ban with a
		/// valid proof nor extend it with a bad one.
		refusal: Option<ScramRefusal>,
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

	/// Toggle the `[auth] scram` knob for this listener. `true` keeps the
	/// default behaviour (both SCRAM-SHA-256 and `-PLUS` advertised when
	/// channel binding is available); `false` hides both on the wire and
	/// refuses an explicit `AUTHENTICATE` against them.
	pub fn with_scram_enabled(mut self, enabled: bool) -> Self {
		self.scram_enabled = enabled;
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
	pub(super) fn capabilities(&self) -> String {
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
		let proof = bearer_proof(self.oauth.as_deref());
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
				// The account rules (disabled, protocol allowlist) apply to a
				// bearer token as to a password, with the same wire outcome as
				// an unverifiable token.
				self.directory
					.admit_login(&account, self.auth_protocol, proof)
					.then_some(account)
			});
		match outcome {
			Some(account) => self.auth_success(tag, account, "AUTHENTICATE completed"),
			None => self.auth_failure(tag),
		}
	}

	/// Begin AUTHENTICATE. AUTHENTICATE requires TLS and the unauthenticated
	/// state, like LOGIN.
	pub(super) fn auth(&mut self, tag: &str, mechanism: &str, initial: Option<Secret>) -> Output {
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
			Ok(address) => match self.directory.resolve(&address) {
				crate::smtp::directory::Resolution::Account(account) => account,
				_ => return self.auth_failure(tag),
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
			self.record_scram_outcome("", None, false, false);
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
			self.record_scram_outcome("", None, false, false);
			return self.auth_failure(tag);
		};
		// The directory plans the whole exchange: the ban check comes before
		// any credential lookup, and an account that may not sign in with
		// SCRAM (disabled, second factor, protocol not allowed) or a login
		// under a ban gets decoy credentials. Either way the wire shows the
		// same `+` continuation and then a `NO` at client-final, exactly as a
		// wrong proof would, so nothing tells a refusal from a bad password.
		let plan = self
			.directory
			.plan_scram(&username, self.peer_ip, self.auth_protocol);
		let Some(nonce) = self.fresh_nonce() else {
			// CSPRNG failure: fail closed rather than use a predictable nonce.
			self.count_scram_failure(&username, &plan);
			return self.auth_failure(tag);
		};
		let mut server = ScramServer::new(nonce).with_channel_binding(binding);
		let Ok((_user, server_first)) = server.first(&client_first, &plan.credentials) else {
			self.count_scram_failure(&username, &plan);
			return self.auth_failure(tag);
		};
		self.pending_auth = Some(PendingAuth::ScramFinal {
			tag: tag.to_string(),
			server: Box::new(server),
			credentials: Box::new(plan.credentials),
			account: plan.account,
			refusal: plan.refusal,
		});
		continuation(&BASE64.encode(server_first))
	}

	/// Count a failure that ends an exchange before the proof, unless a ban
	/// caused it: a ban refusal never moves the strike count.
	fn count_scram_failure(&self, username: &str, plan: &ScramPlan) {
		match &plan.refusal {
			Some(ScramRefusal::Banned) => {}
			Some(ScramRefusal::Denied { account }) => {
				self.record_scram_outcome(username, account.as_deref(), false, false);
			}
			None => self.record_scram_outcome(username, Some(&plan.account), false, false),
		}
	}

	#[allow(clippy::too_many_arguments)]
	fn scram_final(
		&mut self,
		tag: &str,
		encoded: &str,
		mut server: ScramServer,
		credentials: ScramCredentials,
		account: &str,
		refusal: Option<ScramRefusal>,
	) -> Output {
		// A refused exchange stays refused at client-final. A ban that was in
		// force at client-first holds even if it has since expired: a banned
		// subject must not clear the row with a valid proof (the credentials
		// here are decoys) nor extend it with a bad one (no strike is
		// recorded). An account the rules refuse ends as one failed attempt.
		// The recheck below catches a ban that fires after the client-first.
		match refusal {
			Some(ScramRefusal::Banned) => return self.auth_failure(tag),
			Some(ScramRefusal::Denied { account: counted }) => {
				self.record_scram_outcome(account, counted.as_deref(), false, false);
				return self.auth_failure(tag);
			}
			None => {}
		}
		// The recheck at client-final: a ban that fired between
		// client-first and client-final still refuses the exchange,
		// because `Banned` is only emitted when the ban is in force at
		// the time of the check.
		// The flag that decides whether the success lifts the ban rows
		// comes from THIS check, not from any value carried from
		// client-first: between the two messages a ban can fire
		// (turning a `Clear` into a `Banned` that the recheck refuses)
		// or lapse (turning a `BannedButKnown` into a `Clear` that
		// lifts the ban as a normal success would).
		let bypassed = match self
			.directory
			.check_ban(account, self.peer_ip, self.auth_protocol)
		{
			BanOutcome::Banned => return self.auth_failure(tag),
			BanOutcome::BannedButKnown { .. } => true,
			BanOutcome::Clear { .. } => false,
		};
		let Some(client_final) = decode(encoded) else {
			self.record_scram_outcome(account, Some(account), false, false);
			return self.auth_failure(tag);
		};
		match server.finish(&client_final, &credentials) {
			Ok(server_final) => {
				// Clear the ban store for both subjects on a successful
				// proof; the ban check at client-first already consulted
				// the store with the same keys, so the success here undoes
				// any in-flight strikes the same way the PLAIN path does.
				// A bypass lift keeps the ban row in force: only the
				// bypass list gets refreshed.
				self.record_scram_outcome(account, Some(account), true, bypassed);
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
				self.record_scram_outcome(account, Some(account), false, false);
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
	/// success clears both subjects unless the proof was a bypass lift
	/// (`bypassed = true`), in which case only the bypass list is
	/// refreshed; a failure records a strike against both. The ban
	/// check at the start of the exchange already decided whether to
	/// refuse the attempt; a ban refusal never reaches this helper, so
	/// the strike count and ban expiry stay where they were.
	fn record_scram_outcome(
		&self,
		login: &str,
		account: Option<&str>,
		success: bool,
		bypassed: bool,
	) {
		self.directory.record_ban_outcome(
			login,
			account,
			success,
			bypassed,
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
