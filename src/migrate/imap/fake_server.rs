//! An in-process IMAP server for the migration tests: just enough of the
//! protocol to serve folders, flags, INTERNALDATE and bodies, with faults
//! that can be switched on to misbehave in the ways a hostile or broken
//! server would.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::CertificateDer;

use super::transport::{Endpoint, Security, Verify};

/// The login the fake server accepts.
pub(super) const USER: &str = "alice@old.example";

/// One stored message.
#[derive(Debug, Clone)]
pub(super) struct Message {
	pub(super) uid: u32,
	pub(super) flags: String,
	pub(super) internal_date: String,
	pub(super) body: Vec<u8>,
	/// RFC822.SIZE to announce instead of the real one.
	pub(super) claimed_size: Option<u64>,
}

impl Message {
	pub(super) fn new(uid: u32, flags: &str, date: &str, body: &[u8]) -> Self {
		Message {
			uid,
			flags: flags.to_string(),
			internal_date: date.to_string(),
			body: body.to_vec(),
			claimed_size: None,
		}
	}
}

/// One folder.
#[derive(Debug, Clone)]
pub(super) struct Folder {
	pub(super) name: String,
	pub(super) attributes: String,
	pub(super) uid_validity: u32,
	pub(super) messages: Vec<Message>,
}

impl Folder {
	pub(super) fn new(name: &str, attributes: &str, messages: Vec<Message>) -> Self {
		Folder {
			name: name.to_string(),
			attributes: attributes.to_string(),
			uid_validity: 1000,
			messages,
		}
	}
}

/// A misbehaviour, triggered once and then cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fault {
	/// Behave.
	None,
	/// On the `fetch`-th body fetch (1-based), drop the connection after
	/// sending `after` bodies.
	DropDuringFetch { fetch: u32, after: u32 },
	/// Announce a literal of `size` octets in the next body fetch.
	HugeLiteral { size: u64 },
	/// Send a line of `size` octets in the next body fetch.
	LongLine { size: usize },
}

/// How the fake server protects its port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
	Tls,
	StartTls,
	/// STARTTLS, but plaintext follows the OK before the handshake.
	StartTlsInjected,
	/// Plaintext without STARTTLS.
	Plain,
}

struct Shared {
	folders: Vec<Folder>,
	delimiter: char,
	password: String,
	fault: Fault,
	body_fetches: u32,
	/// Every authentication attempt that reached the server.
	logins: u32,
}

/// A running fake server.
pub(super) struct FakeServer {
	address: SocketAddr,
	cert: CertificateDer<'static>,
	shared: Arc<Mutex<Shared>>,
}

impl FakeServer {
	/// Start serving `folders` on a loopback port.
	pub(super) async fn start(mode: Mode, delimiter: char, folders: Vec<Folder>) -> Self {
		let (acceptor, cert) = crate::tls::test_support::acceptor_and_cert();
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
		let address = listener.local_addr().expect("address");
		let shared = Arc::new(Mutex::new(Shared {
			folders,
			delimiter,
			password: crate::test_fixtures::password().to_string(),
			fault: Fault::None,
			body_fetches: 0,
			logins: 0,
		}));
		let state = Arc::clone(&shared);
		tokio::spawn(async move {
			while let Ok((tcp, _)) = listener.accept().await {
				let (state, acceptor) = (Arc::clone(&state), acceptor.clone());
				tokio::spawn(async move {
					let stream: Box<dyn Io> = match mode {
						Mode::Tls => match acceptor.accept(tcp).await {
							Ok(tls) => Box::new(tls),
							Err(_) => return,
						},
						Mode::StartTls | Mode::StartTlsInjected | Mode::Plain => Box::new(tcp),
					};
					let starttls =
						matches!(mode, Mode::StartTls | Mode::StartTlsInjected).then_some(acceptor);
					let inject = mode == Mode::StartTlsInjected;
					let _ = serve(stream, starttls, inject, state).await;
				});
			}
		});
		FakeServer {
			address,
			cert,
			shared,
		}
	}

	/// The server's certificate.
	pub(super) fn cert(&self) -> CertificateDer<'static> {
		self.cert.clone()
	}

	/// An endpoint for this server, trusting its certificate.
	pub(super) fn endpoint(&self, security: Security) -> Endpoint {
		Endpoint {
			host: "mail.example.org".to_string(),
			port: self.address.port(),
			address: Some(self.address),
			security,
			verify: Verify::Roots {
				extra: vec![self.cert.clone()],
			},
		}
	}

	pub(super) fn set_fault(&self, fault: Fault) {
		self.shared.lock().expect("lock").fault = fault;
	}

	pub(super) fn logins(&self) -> u32 {
		self.shared.lock().expect("lock").logins
	}

	/// Change the folders while the server runs.
	pub(super) fn edit(&self, edit: impl FnOnce(&mut Vec<Folder>)) {
		edit(&mut self.shared.lock().expect("lock").folders);
	}
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

async fn serve(
	stream: Box<dyn Io>,
	mut starttls: Option<TlsAcceptor>,
	inject: bool,
	shared: Arc<Mutex<Shared>>,
) -> std::io::Result<()> {
	let mut conn = BufReader::new(stream);
	let caps = |tls_offer: bool| {
		let mut caps =
			"IMAP4rev1 AUTH=PLAIN SASL-IR NAMESPACE SPECIAL-USE LIST-EXTENDED".to_string();
		if tls_offer {
			caps.push_str(" STARTTLS");
		}
		caps
	};
	conn.get_mut()
		.write_all(
			format!(
				"* OK [CAPABILITY {}] fake ready\r\n",
				caps(starttls.is_some())
			)
			.as_bytes(),
		)
		.await?;
	let mut selected: Option<usize> = None;
	let mut line = String::new();
	loop {
		line.clear();
		if conn.read_line(&mut line).await? == 0 {
			return Ok(());
		}
		let text = line.trim_end().to_string();
		let (tag, rest) = text.split_once(' ').unwrap_or((&text, ""));
		let (command, args) = rest.split_once(' ').unwrap_or((rest, ""));
		let mut out = Vec::new();
		match command.to_ascii_uppercase().as_str() {
			"CAPABILITY" => {
				out.extend(format!("* CAPABILITY {}\r\n", caps(starttls.is_some())).bytes());
			}
			"STARTTLS" if starttls.is_some() => {
				let acceptor = starttls.take().expect("acceptor");
				let mut answer = format!("{tag} OK begin TLS\r\n");
				if inject {
					answer.push_str("* 1 EXISTS\r\n");
				}
				conn.get_mut().write_all(answer.as_bytes()).await?;
				let tls = acceptor.accept(conn.into_inner()).await?;
				conn = BufReader::new(Box::new(tls));
				continue;
			}
			"AUTHENTICATE" => {
				let expected = {
					let mut state = shared.lock().expect("lock");
					state.logins += 1;
					format!("\0{USER}\0{}", state.password)
				};
				let given = args
					.strip_prefix("PLAIN ")
					.and_then(|b64| {
						use base64::Engine;
						base64::engine::general_purpose::STANDARD.decode(b64).ok()
					})
					.unwrap_or_default();
				if given == expected.as_bytes() {
					out.extend(format!("{tag} OK logged in\r\n").bytes());
				} else {
					out.extend(
						format!("{tag} NO [AUTHENTICATIONFAILED] invalid credentials\r\n").bytes(),
					);
				}
				conn.get_mut().write_all(&out).await?;
				continue;
			}
			"NAMESPACE" => {
				let delimiter = shared.lock().expect("lock").delimiter;
				out.extend(format!("* NAMESPACE ((\"\" \"{delimiter}\")) NIL NIL\r\n").bytes());
			}
			"LIST" => {
				// Special-use attributes only when asked for, as RFC 6154
				// allows, so the client has to ask.
				let special = args.contains("RETURN (SPECIAL-USE)");
				let state = shared.lock().expect("lock");
				for folder in &state.folders {
					let attributes: Vec<&str> = folder
						.attributes
						.split(' ')
						.filter(|a| {
							special
								|| matches!(*a, "\\HasChildren" | "\\HasNoChildren" | "\\Noselect")
						})
						.collect();
					out.extend(
						format!(
							"* LIST ({}) \"{}\" \"{}\"\r\n",
							attributes.join(" "),
							state.delimiter,
							folder.name
						)
						.bytes(),
					);
				}
			}
			"EXAMINE" => {
				let name = args.trim_matches('"');
				{
					let state = shared.lock().expect("lock");
					match state.folders.iter().position(|f| f.name == name) {
						Some(index) => {
							let folder = &state.folders[index];
							selected = Some(index);
							out.extend(format!("* {} EXISTS\r\n", folder.messages.len()).bytes());
							out.extend(
								format!(
									"* OK [UIDVALIDITY {}] UIDs valid\r\n",
									folder.uid_validity
								)
								.bytes(),
							);
							out.extend(format!("{tag} OK [READ-ONLY] done\r\n").bytes());
						}
						None => out.extend(format!("{tag} NO no such mailbox\r\n").bytes()),
					}
				}
				conn.get_mut().write_all(&out).await?;
				continue;
			}
			"UID" => {
				let Some(index) = selected else {
					out.extend(format!("{tag} BAD nothing selected\r\n").bytes());
					conn.get_mut().write_all(&out).await?;
					continue;
				};
				let (_, fetch_args) = args.split_once(' ').unwrap_or(("", ""));
				let (set, items) = fetch_args.split_once(' ').unwrap_or((fetch_args, ""));
				let with_body = items.contains("BODY.PEEK[]");
				if !fetch(&mut conn, &shared, index, set, with_body).await? {
					return Ok(());
				}
			}
			"LOGOUT" => {
				out.extend(b"* BYE bye\r\n");
				out.extend(format!("{tag} OK logged out\r\n").bytes());
				conn.get_mut().write_all(&out).await?;
				return Ok(());
			}
			_ => {
				out.extend(format!("{tag} BAD unknown command\r\n").bytes());
				conn.get_mut().write_all(&out).await?;
				continue;
			}
		}
		out.extend(format!("{tag} OK done\r\n").bytes());
		conn.get_mut().write_all(&out).await?;
	}
}

/// Answer a UID FETCH. `false` when a fault dropped the connection.
async fn fetch(
	conn: &mut BufReader<Box<dyn Io>>,
	shared: &Arc<Mutex<Shared>>,
	index: usize,
	set: &str,
	with_body: bool,
) -> std::io::Result<bool> {
	let (messages, fault, fetch_number) = {
		let mut state = shared.lock().expect("lock");
		let fetch_number = if with_body {
			state.body_fetches += 1;
			state.body_fetches
		} else {
			0
		};
		let fault = state.fault;
		(state.folders[index].messages.clone(), fault, fetch_number)
	};
	let wanted = matching(&messages, set);
	let mut sent_bodies = 0;
	for (sequence, message) in messages.iter().enumerate() {
		if !wanted.contains(&message.uid) {
			continue;
		}
		let size = message.claimed_size.unwrap_or(message.body.len() as u64);
		if !with_body {
			let line = format!(
				"* {} FETCH (UID {} RFC822.SIZE {size})\r\n",
				sequence + 1,
				message.uid
			);
			conn.get_mut().write_all(line.as_bytes()).await?;
			continue;
		}
		match fault {
			Fault::DropDuringFetch { fetch, after }
				if fetch == fetch_number && after == sent_bodies =>
			{
				shared.lock().expect("lock").fault = Fault::None;
				conn.get_mut().shutdown().await?;
				return Ok(false);
			}
			Fault::HugeLiteral { size } => {
				shared.lock().expect("lock").fault = Fault::None;
				let line = format!(
					"* {} FETCH (UID {} BODY[] {{{size}}}\r\n",
					sequence + 1,
					message.uid
				);
				conn.get_mut().write_all(line.as_bytes()).await?;
				conn.get_mut().write_all(&vec![b'x'; 4096]).await?;
				return Ok(false);
			}
			Fault::LongLine { size } => {
				shared.lock().expect("lock").fault = Fault::None;
				let mut line =
					format!("* {} FETCH (UID {} X-JUNK ", sequence + 1, message.uid).into_bytes();
				line.extend(std::iter::repeat_n(b'a', size));
				conn.get_mut().write_all(&line).await?;
				return Ok(false);
			}
			_ => {}
		}
		let head = format!(
			"* {} FETCH (UID {} FLAGS ({}) INTERNALDATE \"{}\" RFC822.SIZE {size} BODY[] {{{}}}\r\n",
			sequence + 1,
			message.uid,
			message.flags,
			message.internal_date,
			message.body.len()
		);
		conn.get_mut().write_all(head.as_bytes()).await?;
		conn.get_mut().write_all(&message.body).await?;
		conn.get_mut().write_all(b")\r\n").await?;
		sent_bodies += 1;
	}
	Ok(true)
}

/// The UIDs of `messages` a UID set names. `n:*` with `n` past the last
/// UID still names the last message, as RFC 9051 says.
fn matching(messages: &[Message], set: &str) -> Vec<u32> {
	let highest = messages.iter().map(|m| m.uid).max().unwrap_or(0);
	let value = |text: &str| {
		if text == "*" {
			highest
		} else {
			text.parse().unwrap_or(0)
		}
	};
	let mut uids = Vec::new();
	for part in set.split(',') {
		let (low, high) = match part.split_once(':') {
			Some((a, b)) => {
				let (a, b) = (value(a), value(b));
				(a.min(b), a.max(b))
			}
			None => (value(part), value(part)),
		};
		uids.extend(
			messages
				.iter()
				.map(|m| m.uid)
				.filter(|uid| (low..=high).contains(uid)),
		);
	}
	uids
}
