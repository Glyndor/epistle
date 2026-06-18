//! IMAP AUTHENTICATE: PLAIN and SCRAM-SHA-256 (RFC 9051, RFC 5802).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::smtp::scram::{ScramCredentials, ScramServer, username_of};

use super::{Output, Session, State};

/// In-flight SASL state between AUTHENTICATE continuation lines.
pub(super) enum PendingAuth {
	/// Tag stashed while awaiting the PLAIN response (`+ `).
	Plain { tag: String },
	/// Awaiting the SCRAM client-first message.
	ScramFirst { tag: String },
	/// Awaiting the SCRAM client-final message.
	ScramFinal {
		tag: String,
		server: Box<ScramServer>,
		credentials: Box<ScramCredentials>,
		account: String,
	},
}

impl Session {
	/// Inject a fixed SCRAM server nonce (tests/determinism).
	pub fn with_scram_nonce(mut self, nonce: &str) -> Self {
		self.scram_nonce = Some(nonce.to_string());
		self
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
			"SCRAM-SHA-256" => match initial {
				Some(client_first) => self.scram_first(tag, &client_first),
				None => {
					self.pending_auth = Some(PendingAuth::ScramFirst {
						tag: tag.to_string(),
					});
					continuation("")
				}
			},
			_ => Output::text(format!("{tag} NO unsupported SASL mechanism\r\n")),
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
			Some(PendingAuth::ScramFirst { tag }) => self.scram_first(&tag, line),
			Some(PendingAuth::ScramFinal {
				tag,
				server,
				credentials,
				account,
			}) => self.scram_final(&tag, line, *server, *credentials, &account),
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

	fn scram_first(&mut self, tag: &str, encoded: &str) -> Output {
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
		let mut server = ScramServer::new(self.fresh_nonce());
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
			Some(PendingAuth::Plain { tag } | PendingAuth::ScramFirst { tag }) => tag.clone(),
			Some(PendingAuth::ScramFinal { tag, .. }) => tag.clone(),
			None => "*".to_string(),
		}
	}

	fn fresh_nonce(&self) -> String {
		if let Some(nonce) = &self.scram_nonce {
			return nonce.clone();
		}
		use ring::rand::SecureRandom;
		let mut bytes = [0u8; 18];
		let _ = ring::rand::SystemRandom::new().fill(&mut bytes);
		BASE64.encode(bytes)
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
