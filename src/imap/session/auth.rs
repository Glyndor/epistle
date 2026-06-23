//! IMAP AUTHENTICATE: PLAIN and SCRAM-SHA-256 (RFC 9051, RFC 5802).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::smtp::scram::{ChannelBinding, ScramCredentials, ScramServer, username_of};

use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;

use super::{Output, Session, State};

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
	},
	/// AUTH=LOGIN: awaiting the base64 username.
	LoginUser { tag: String },
	/// AUTH=LOGIN: awaiting the base64 password for `user`.
	LoginPass { tag: String, user: String },
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
		let mut caps = String::new();
		// Channel binding (-PLUS) is offered only with a certificate hash to bind.
		if self.cbind_data.is_some() {
			caps.push_str(" AUTH=SCRAM-SHA-256-PLUS");
		}
		caps.push_str(" AUTH=PLAIN AUTH=LOGIN AUTH=SCRAM-SHA-256");
		if self.oauth.is_some() {
			caps.push_str(" AUTH=OAUTHBEARER AUTH=XOAUTH2");
		}
		caps.push_str(" SASL-IR");
		caps
	}

	/// The advertised IMAP capabilities, including SASL mechanisms and the
	/// STARTTLS/LOGINDISABLED state.
	pub(super) fn capabilities(&self) -> String {
		let mut capabilities = String::from(
			"IMAP4rev2 MOVE IDLE LITERAL+ SPECIAL-USE NAMESPACE ID UIDPLUS SORT \
THREAD=ORDEREDSUBJECT UNSELECT ENABLE ESEARCH MULTISEARCH QUOTA QUOTA=RES-STORAGE STATUS=SIZE CONDSTORE LIST-EXTENDED \
LIST-STATUS BINARY QRESYNC OBJECTID SAVEDATE PREVIEW REPLACE ACL RIGHTS=texk METADATA",
		);
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
		let outcome = self.oauth.clone().zip(initial).and_then(|(verifier, enc)| {
			let token = parse_bearer(&enc)?;
			let email = verifier.verify(&token, unix_now())?;
			let address = Address::parse(&email).ok()?;
			match self.directory.resolve(&address) {
				Resolution::Account(account) => Some(account),
				_ => None,
			}
		});
		match outcome {
			Some(account) => {
				self.state = State::Authenticated { account };
				Output::text(format!("{tag} OK AUTHENTICATE completed\r\n"))
			}
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
		match mechanism {
			"PLAIN" => match initial {
				Some(response) => self.auth_plain(tag, &response),
				None => {
					self.pending_auth = Some(PendingAuth::Plain {
						tag: tag.to_string(),
					});
					continuation("")
				}
			},
			"SCRAM-SHA-256" => self.scram_begin(tag, initial, false),
			"SCRAM-SHA-256-PLUS" if self.cbind_data.is_some() => {
				self.scram_begin(tag, initial, true)
			}
			"LOGIN" => match initial {
				// SASL-IR initial response is the username.
				Some(user) => self.login_user(tag, &user),
				None => {
					self.pending_auth = Some(PendingAuth::LoginUser {
						tag: tag.to_string(),
					});
					continuation("VXNlcm5hbWU6")
				}
			},
			"OAUTHBEARER" | "XOAUTH2" => self.oauth_bearer(tag, initial),
			_ => Output::text(format!("{tag} NO unsupported SASL mechanism\r\n")),
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

	/// AUTH=LOGIN: verify the password (plus any TOTP) against the username.
	fn login_pass(&mut self, tag: &str, user: &str, encoded: &str) -> Output {
		let verified = decode(encoded).and_then(|pass| self.directory.authenticate(user, &pass));
		match verified {
			Some(account) => {
				self.state = State::Authenticated { account };
				Output::text(format!("{tag} OK AUTHENTICATE completed\r\n"))
			}
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
			}) => self.scram_final(&tag, line, *server, *credentials, &account),
			Some(PendingAuth::LoginUser { tag }) => self.login_user(&tag, line),
			Some(PendingAuth::LoginPass { tag, user }) => self.login_pass(&tag, &user, line),
			None => Output::text("* BAD unexpected authentication response\r\n".to_string()),
		}
	}

	fn auth_plain(&mut self, tag: &str, encoded: &str) -> Output {
		let verified = crate::smtp::auth::parse_plain(encoded)
			.ok()
			.and_then(|creds| {
				self.directory
					.credentials(&creds.authcid)
					.filter(|(_, hash)| crate::smtp::auth::verify_password(hash, &creds.password))
					.map(|(account, _)| account)
			});
		match verified {
			Some(account) => {
				self.state = State::Authenticated { account };
				Output::text(format!("{tag} OK AUTHENTICATE completed\r\n"))
			}
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
			return self.auth_failure(tag);
		};
		let Some(username) = username_of(&client_first) else {
			return self.auth_failure(tag);
		};
		let Some(credentials) = self.directory.scram_credentials(&username) else {
			return self.auth_failure(tag);
		};
		let Some((account, _)) = self.directory.credentials(&username) else {
			return self.auth_failure(tag);
		};
		let Some(nonce) = self.fresh_nonce() else {
			// CSPRNG failure: fail closed rather than use a predictable nonce.
			return self.auth_failure(tag);
		};
		let mut server = ScramServer::new(nonce).with_channel_binding(binding);
		let Ok((_user, server_first)) = server.first(&client_first, &credentials) else {
			return self.auth_failure(tag);
		};
		self.pending_auth = Some(PendingAuth::ScramFinal {
			tag: tag.to_string(),
			server: Box::new(server),
			credentials: Box::new(credentials),
			account,
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
	) -> Output {
		let Some(client_final) = decode(encoded) else {
			return self.auth_failure(tag);
		};
		match server.finish(&client_final, &credentials) {
			Ok(server_final) => {
				self.state = State::Authenticated {
					account: account.to_string(),
				};
				Output::text(format!(
					"{tag} OK [SASL {}] AUTHENTICATE completed\r\n",
					BASE64.encode(server_final)
				))
			}
			Err(_) => self.auth_failure(tag),
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

	fn pending_auth_tag(&self) -> String {
		match &self.pending_auth {
			Some(
				PendingAuth::Plain { tag }
				| PendingAuth::ScramFirst { tag, .. }
				| PendingAuth::LoginUser { tag },
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
