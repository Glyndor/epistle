//! The `probe` subcommand: a quick, local healthcheck for the listeners
//! the running server has bound. TCP connects to loopback addresses with a
//! short timeout, the greeting line read back and checked against
//! the protocol the listener advertises. Exit 0 if every listener
//! responded with a recognisable greeting, 1 if any failed.
//!
//! The probe runs as the same user the listeners bound on; it does not
//! escalate privileges, ask for credentials, or send any mail. It
//! exists so the distroless container image (which only ships
//! `/usr/bin/epistle`, no shell, no curl) can answer the container
//! engine's healthcheck: the generated compose binds the
//! `["CMD", "/usr/bin/epistle", "probe", "--config", <path>]` form.
//!
//! Each probe speaks the wire the listener advertises: SMTP/IMAP/POP3
//! read the first line the server sends; HTTP listeners get a
//! `HEAD / HTTP/1.0` request and read the response status line;
//! `submissions` / `imaps` / `pop3s` open a TLS session first using
//! an unverified verifier so a self-signed certificate works without
//! provisioning trust anchors for the probe. The probe only has to
//! prove the server is up and answering its protocol.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls;

use crate::config::{Config, Listener, ListenerKind};
use crate::tls::ensure_crypto_provider;

/// Per-listener timeout. Two seconds: long
/// enough to ride out a slow first byte from a freshly-started
/// listener, short enough that a stuck TLS handshake cannot wedge the
/// healthcheck past the engine's own probe interval.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum bytes the probe will buffer when reading a greeting or
/// response line. The server's first banner and the HTTP status line
/// fit in tens of bytes; a 4 KiB ceiling stops a misbehaving peer from
/// making the probe allocate forever.
const READ_CAP: usize = 4096;

/// What one probe saw. Used both for the human-readable output line
/// (`ok <kind> <addr>` / `fail <kind> <addr>: <reason>`) and as the
/// element shape for `--json`.
#[derive(Debug, Serialize)]
pub(super) struct ProbeLine {
	pub(super) kind: &'static str,
	pub(super) addr: String,
	pub(super) ok: bool,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) error: Option<String>,
}

/// Run the `probe` command. Loads the configuration file, dials each
/// configured listener on its loopback equivalent, and reports.
/// Returns the exit code the dispatcher should propagate: SUCCESS
/// when every listener answered, FAILURE when at least one did not.
pub(super) fn run(config: &Config, json: bool) -> ExitCode {
	ensure_crypto_provider();
	let cert_path = pinned_cert_path(config);
	let results = match execute(&config.listeners, cert_path.as_deref()) {
		Ok(results) => results,
		Err(error) => {
			super::style::error(format_args!("probe: {error}"));
			return ExitCode::FAILURE;
		}
	};
	render(&results, json);
	if results.iter().all(|line| line.ok) {
		ExitCode::SUCCESS
	} else {
		ExitCode::FAILURE
	}
}

/// The certificate file the probe pins: the one `serve` presents.
pub(super) fn pinned_cert_path(config: &Config) -> Option<PathBuf> {
	crate::tls::served_tls(config).map(|served| served.tls.cert_file)
}

/// Drive every listener probe from inside a one-thread runtime. The
/// runtime is required because the production call site (the CLI
/// subcommand) is synchronous; tests run the [`probe_all`] async
/// function directly on the `#[tokio::test]` runtime instead.
fn execute(
	listeners: &[Listener],
	tls_cert_path: Option<&Path>,
) -> std::io::Result<Vec<ProbeLine>> {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.map_err(|error| std::io::Error::other(format!("build probe runtime: {error}")))?;
	runtime.block_on(probe_all(listeners, tls_cert_path))
}

/// Probe every listener sequentially, returning one entry per listener
/// in input order. Sequential because there are typically only a
/// handful of listeners and the connections are short; spawning one
/// task per listener would not buy anything measurable here.
///
/// `tls_cert_path` is the path the operator has configured under
/// `[tls] cert_file`. The apply phase writes either
/// `<data_dir>/keys/cert.pem` for a static configuration or
/// `<data_dir>/acme/cert.pem` once ACME renewal takes over, so the
/// probe reads it straight from the parsed config and pins the
/// verifier against it. `None` is the no-TLS-configured case; TLS
/// listeners under that config still fail the probe, with a reason.
pub(super) async fn probe_all(
	listeners: &[Listener],
	tls_cert_path: Option<&Path>,
) -> std::io::Result<Vec<ProbeLine>> {
	let pinned = build_verifier(tls_cert_path);
	let mut out = Vec::with_capacity(listeners.len());
	for listener in listeners {
		let line = probe_one(listener, &pinned).await;
		out.push(line);
	}
	Ok(out)
}

async fn probe_one(
	listener: &Listener,
	pinned: &Option<Result<Arc<dyn ServerCertVerifier>, String>>,
) -> ProbeLine {
	let socket = listener.socket_addr();
	let mut addr = SocketAddr::new(loopback_for(listener.addr), socket.port());
	let kind = listener.kind.as_str();
	let result = match connect_listener_with(listener, tcp_connect).await {
		Ok((stream, answered)) => {
			addr = answered;
			probe_kind(listener, stream, pinned).await
		}
		Err(error) => Err(format!("connect: {error}")),
	};
	match result {
		Ok(()) => ProbeLine {
			kind,
			addr: addr.to_string(),
			ok: true,
			error: None,
		},
		Err(reason) => ProbeLine {
			kind,
			addr: addr.to_string(),
			ok: false,
			error: Some(reason),
		},
	}
}

/// Replace an unspecified bind address (`0.0.0.0` or `::`) with the
/// matching loopback: `127.0.0.1` for an IPv4 listener, `::1` for an
/// IPv6 listener. Anything else passes through unchanged so an
/// operator who bound the listener to a specific address (e.g.
/// `127.0.0.5`) is probed on that exact address.
fn loopback_for(addr: IpAddr) -> IpAddr {
	match addr {
		IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
		IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
		other => other,
	}
}

async fn connect_listener_with<S, F, Fut>(
	listener: &Listener,
	mut connect: F,
) -> std::io::Result<(S, SocketAddr)>
where
	F: FnMut(SocketAddr) -> Fut,
	Fut: std::future::Future<Output = std::io::Result<S>>,
{
	let addr = SocketAddr::new(loopback_for(listener.addr), listener.socket_addr().port());
	match connect(addr).await {
		Ok(stream) => Ok((stream, addr)),
		Err(error)
			if listener.addr == IpAddr::V6(Ipv6Addr::UNSPECIFIED)
				&& matches!(
					error.kind(),
					std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut
				) =>
		{
			// Container port publishing may expose only IPv4 on the host.
			let ipv4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port());
			connect(ipv4).await.map(|stream| (stream, ipv4))
		}
		Err(error) => Err(error),
	}
}

async fn probe_kind(
	listener: &Listener,
	stream: TcpStream,
	pinned: &Option<Result<Arc<dyn ServerCertVerifier>, String>>,
) -> Result<(), String> {
	match listener.kind {
		ListenerKind::Smtp => probe_smtp(stream).await,
		ListenerKind::Submission => probe_smtp(stream).await,
		ListenerKind::Submissions => probe_submissions(stream, pinned).await,
		ListenerKind::Imap => probe_imap(stream).await,
		ListenerKind::Imaps => probe_imaps(stream, pinned).await,
		ListenerKind::Pop3s => probe_pop3s(stream, pinned).await,
		ListenerKind::Autoconfigs => probe_https(stream, pinned).await,
		ListenerKind::ManageSieve => probe_sieve(stream).await,
		ListenerKind::Api
		| ListenerKind::WebDav
		| ListenerKind::Acme
		| ListenerKind::Autoconfig
		| ListenerKind::Metrics => probe_http(stream).await,
	}
}

async fn probe_smtp(mut stream: TcpStream) -> Result<(), String> {
	check_smtp_banner(&mut stream).await
}

async fn probe_submissions(
	stream: TcpStream,
	pinned: &Option<Result<Arc<dyn ServerCertVerifier>, String>>,
) -> Result<(), String> {
	let verifier = require_verifier(pinned)?;
	let mut stream = tls_handshake(stream, verifier).await?;
	check_smtp_banner(&mut stream).await
}

async fn check_smtp_banner<R>(reader: &mut R) -> Result<(), String>
where
	R: AsyncReadExt + Unpin,
{
	let banner = read_line(reader).await?;
	let banner = banner.trim_end_matches(['\r', '\n']);
	if banner.starts_with("220 ") {
		Ok(())
	} else {
		Err(format!("expected SMTP 220 banner, got {banner:?}"))
	}
}

async fn probe_imap(mut stream: TcpStream) -> Result<(), String> {
	check_imap_greeting(&mut stream).await
}

async fn probe_imaps(
	stream: TcpStream,
	pinned: &Option<Result<Arc<dyn ServerCertVerifier>, String>>,
) -> Result<(), String> {
	let verifier = require_verifier(pinned)?;
	let mut stream = tls_handshake(stream, verifier).await?;
	check_imap_greeting(&mut stream).await
}

async fn check_imap_greeting<R>(reader: &mut R) -> Result<(), String>
where
	R: AsyncReadExt + Unpin,
{
	let greeting = read_line(reader).await?;
	let greeting = greeting.trim_end_matches(['\r', '\n']);
	if greeting.starts_with("* OK") {
		Ok(())
	} else {
		Err(format!("expected IMAP `* OK` greeting, got {greeting:?}"))
	}
}

async fn probe_pop3s(
	stream: TcpStream,
	pinned: &Option<Result<Arc<dyn ServerCertVerifier>, String>>,
) -> Result<(), String> {
	let verifier = require_verifier(pinned)?;
	let mut stream = tls_handshake(stream, verifier).await?;
	let greeting = read_line(&mut stream).await?;
	let greeting = greeting.trim_end_matches(['\r', '\n']);
	if greeting.starts_with("+OK") {
		Ok(())
	} else {
		Err(format!("expected POP3 `+OK` greeting, got {greeting:?}"))
	}
}

async fn probe_sieve(mut stream: TcpStream) -> Result<(), String> {
	let greeting = read_line(&mut stream).await?;
	let greeting = greeting.trim_end_matches(['\r', '\n']);
	// ManageSieve greets with an `OK` capability-list line; it does
	// not send STARTTLS up-front, so a plaintext probe is enough.
	if greeting.trim_start().starts_with("OK") {
		Ok(())
	} else {
		Err(format!(
			"expected ManageSieve `OK` greeting, got {greeting:?}"
		))
	}
}

async fn probe_https(
	stream: TcpStream,
	pinned: &Option<Result<Arc<dyn ServerCertVerifier>, String>>,
) -> Result<(), String> {
	let verifier = require_verifier(pinned)?;
	probe_http(tls_handshake(stream, verifier).await?).await
}

async fn probe_http<S>(mut stream: S) -> Result<(), String>
where
	S: AsyncReadExt + AsyncWriteExt + Unpin,
{
	// `HEAD /` is the cheapest request that elicits a real response
	// line. `Connection: close` asks the server to fold the socket
	// after one exchange so the probe does not stall on a keep-alive
	// timeout. The Host header is HTTP/1.1's only required request
	// field and some hosts return 400 without it.
	let request = b"HEAD / HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
	stream
		.write_all(request)
		.await
		.map_err(|error| format!("write probe request: {error}"))?;
	stream
		.flush()
		.await
		.map_err(|error| format!("flush probe request: {error}"))?;
	let status = read_line(&mut stream).await?;
	let status = status.trim_end_matches(['\r', '\n']);
	let Some(rest) = status.strip_prefix("HTTP/") else {
		return Err(format!("expected HTTP response, got {status:?}"));
	};
	// Strip the protocol version (`1.0` or `1.1`) before reading the
	// numeric code, so the line `HTTP/1.1 200 OK` yields the code
	// `200` and not `1.1`.
	let code = rest
		.split_whitespace()
		.nth(1)
		.ok_or_else(|| format!("HTTP status line has no code: {status:?}"))?;
	if code.chars().take(3).all(|c| c.is_ascii_digit()) {
		Ok(())
	} else {
		Err(format!("HTTP status code is not numeric: {status:?}"))
	}
}

async fn tcp_connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
	match timeout(PROBE_TIMEOUT, TcpStream::connect(addr)).await {
		Ok(Ok(stream)) => Ok(stream),
		Ok(Err(error)) => Err(error),
		Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")),
	}
}

/// Open a TLS session on top of an already-connected `stream`. The
/// caller supplies the verifier; the probe-side wrapper
/// ([`PinnedCertVerifier`]) pins the presented certificate to the
/// operator's `[tls] cert_file` so a renewed-but-not-reloaded listener
/// shows up as a fail line, not a silent pass.
async fn tls_handshake(
	stream: TcpStream,
	verifier: Arc<dyn ServerCertVerifier>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
	// rustls's client config builder state machine: `WantsVerifier` is
	// what `ClientConfig::builder()` returns. A custom verifier sits
	// behind `.dangerous()`, and the result is `WantsClientCert`,
	// which closes with `.with_no_client_auth()`. The builder used to
	// require version selection between the verifier step and the
	// client-auth step; that path is now satisfied upstream of this
	// function (`.builder()` ships with `DEFAULT_VERSIONS`).
	let config = ClientConfig::builder()
		.dangerous()
		.with_custom_certificate_verifier(verifier)
		.with_no_client_auth();
	let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
	let server_name =
		ServerName::try_from("localhost").map_err(|error| format!("server name: {error}"))?;
	match timeout(PROBE_TIMEOUT, connector.connect(server_name, stream)).await {
		Ok(Ok(tls)) => Ok(tls),
		Ok(Err(error)) => Err(format!("tls handshake: {error}")),
		Err(_) => Err("tls handshake: timeout".to_string()),
	}
}

/// Certificate verifier for the probe that accepts only the certificate
/// the operator has on disk under `[tls] cert_file`. The cert bytes
/// are the same the apply phase chose: `keys/cert.pem` for a static
/// config, `<data_dir>/acme/cert.pem` once ACME takes over; either way
/// the file the listener binds with is the one TOML points at. When
/// the listener has not reloaded after a renewal, the bytes on the
/// wire no longer match the file on disk and the probe fails with a
/// line that names the path.
///
/// The handshake signatures are still verified for real, against the
/// presented certificate's own key, using the ring provider's
/// algorithms: the pin only authenticates *which* certificate may
/// appear, not the proof the peer holds the matching private key.
pub(crate) struct PinnedCertVerifier {
	/// DER of the leaf certificate in `[tls] cert_file`. The verifier
	/// accepts only a presented certificate whose bytes match exactly.
	expected_der: Vec<u8>,
	/// The path the operator has on disk. Carried so the failure line
	/// can name the file the operator should compare against.
	cert_path: PathBuf,
	/// Crypto provider whose signature algorithms verify the
	/// handshake signatures against the presented certificate.
	provider: Arc<rustls::crypto::CryptoProvider>,
}

impl std::fmt::Debug for PinnedCertVerifier {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("PinnedCertVerifier")
			.field("cert_path", &self.cert_path)
			.finish()
	}
}

impl PinnedCertVerifier {
	/// Build the verifier from `path`. Returns `Err` when the file
	/// cannot be read or has no certificates; the `Display` message
	/// is what the probe prints on the failed listener line.
	pub(crate) fn from_path(path: &Path) -> std::io::Result<Self> {
		let expected_der = crate::tls::leaf_cert_der(path)
			.map_err(|error| std::io::Error::other(format!("{error}")))?;
		Ok(Self {
			expected_der,
			cert_path: path.to_path_buf(),
			provider: default_provider(),
		})
	}
}

fn default_provider() -> Arc<rustls::crypto::CryptoProvider> {
	rustls::crypto::CryptoProvider::get_default()
		.cloned()
		.unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

impl ServerCertVerifier for PinnedCertVerifier {
	fn verify_server_cert(
		&self,
		end_entity: &CertificateDer<'_>,
		_intermediates: &[CertificateDer<'_>],
		_server_name: &ServerName<'_>,
		_ocsp_response: &[u8],
		_now: UnixTime,
	) -> Result<ServerCertVerified, Error> {
		if end_entity.as_ref() != self.expected_der.as_slice() {
			return Err(Error::General(format!(
				"certificate presented differs from {} (not reloaded after renewal?)",
				self.cert_path.display()
			)));
		}
		Ok(ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, Error> {
		rustls::crypto::verify_tls12_signature(
			message,
			cert,
			dss,
			&self.provider.signature_verification_algorithms,
		)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, Error> {
		rustls::crypto::verify_tls13_signature(
			message,
			cert,
			dss,
			&self.provider.signature_verification_algorithms,
		)
	}

	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		self.provider
			.signature_verification_algorithms
			.supported_schemes()
	}
}

/// Outcome of trying to build a [`PinnedCertVerifier`] for the run.
/// `None` means the config has no `[tls]` section (TLS listeners under
/// such a config fail the probe with a clear reason); `Some(Ok(_))`
/// means the verifier is ready; `Some(Err(_))` carries the loader's
/// message so each TLS listener surfaces it verbatim.
fn build_verifier(
	tls_cert_path: Option<&Path>,
) -> Option<Result<Arc<dyn ServerCertVerifier>, String>> {
	let path = tls_cert_path?;
	ensure_crypto_provider();
	Some(
		PinnedCertVerifier::from_path(path)
			.map(|v| Arc::new(v) as Arc<dyn ServerCertVerifier>)
			.map_err(|error| error.to_string()),
	)
}

/// Pull the verifier for a TLS handshake, or return the fail-line
/// reason when no verifier is available.
fn require_verifier(
	pinned: &Option<Result<Arc<dyn ServerCertVerifier>, String>>,
) -> Result<Arc<dyn ServerCertVerifier>, String> {
	match pinned {
		None => Err(
			"no [tls] cert_file configured but a TLS listener listens on the probe address"
				.to_string(),
		),
		Some(Err(error)) => Err(error.clone()),
		Some(Ok(verifier)) => Ok(verifier.clone()),
	}
}

/// Read one line (up to CRLF) from `reader`, bounded by
/// `READ_CAP`. The timeout applies to the whole read, not per byte,
/// so a server that answers an HTTP body but no status line still
/// surfaces as an error.
async fn read_line<R>(reader: &mut R) -> Result<String, String>
where
	R: AsyncReadExt + Unpin,
{
	let mut buf = Vec::with_capacity(128);
	let read = timeout(PROBE_TIMEOUT, async {
		let mut byte = [0u8; 1];
		loop {
			let got = reader
				.read(&mut byte)
				.await
				.map_err(|error| format!("read: {error}"))?;
			if got == 0 {
				return Err("read: peer closed before line".to_string());
			}
			if byte[0] == b'\n' {
				return Ok(());
			}
			if buf.len() >= READ_CAP {
				return Err(format!("read: line longer than {} bytes", READ_CAP));
			}
			buf.push(byte[0]);
		}
	})
	.await;
	match read {
		Ok(Ok(())) => {
			if buf.last() == Some(&b'\r') {
				buf.pop();
			}
			Ok(String::from_utf8(buf).map_err(|_| "read: response is not UTF-8".to_string())?)
		}
		Ok(Err(error)) => Err(error),
		Err(_) => Err("read: timeout".to_string()),
	}
}

fn render(lines: &[ProbeLine], json: bool) {
	if json {
		match serde_json::to_string_pretty(lines) {
			Ok(bytes) => println!("{bytes}"),
			Err(error) => {
				super::style::error(format_args!("probe: encode result: {error}"));
			}
		}
		return;
	}
	for line in lines {
		match &line.error {
			None => println!("ok {} {}", line.kind, line.addr),
			Some(reason) => println!("fail {} {}: {reason}", line.kind, line.addr),
		}
	}
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "probe_tests_pinning.rs"]
mod tests_pinning;

#[cfg(test)]
#[path = "probe_tests_host.rs"]
mod tests_host;
