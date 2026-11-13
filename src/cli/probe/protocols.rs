//! The per-protocol greeting probes.

use super::*;

pub(super) async fn probe_smtp(mut stream: TcpStream) -> Result<(), String> {
	check_smtp_banner(&mut stream).await
}

pub(super) async fn probe_submissions(
	stream: TcpStream,
	pinned: &Option<Result<Arc<dyn ServerCertVerifier>, String>>,
) -> Result<(), String> {
	let verifier = require_verifier(pinned)?;
	let mut stream = tls_handshake(stream, verifier).await?;
	check_smtp_banner(&mut stream).await
}

pub(super) async fn check_smtp_banner<R>(reader: &mut R) -> Result<(), String>
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

pub(super) async fn probe_imap(mut stream: TcpStream) -> Result<(), String> {
	check_imap_greeting(&mut stream).await
}

pub(super) async fn probe_imaps(
	stream: TcpStream,
	pinned: &Option<Result<Arc<dyn ServerCertVerifier>, String>>,
) -> Result<(), String> {
	let verifier = require_verifier(pinned)?;
	let mut stream = tls_handshake(stream, verifier).await?;
	check_imap_greeting(&mut stream).await
}

pub(super) async fn check_imap_greeting<R>(reader: &mut R) -> Result<(), String>
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

pub(super) async fn probe_pop3s(
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

pub(super) async fn probe_sieve(mut stream: TcpStream) -> Result<(), String> {
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

pub(super) async fn probe_https(
	stream: TcpStream,
	pinned: &Option<Result<Arc<dyn ServerCertVerifier>, String>>,
) -> Result<(), String> {
	let verifier = require_verifier(pinned)?;
	probe_http(tls_handshake(stream, verifier).await?).await
}

pub(super) async fn probe_http<S>(mut stream: S) -> Result<(), String>
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
