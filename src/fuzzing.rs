//! Entry points for the cargo-fuzz targets under `fuzz/`.
//!
//! Not an API. The parsers worth fuzzing sit behind crate-private
//! modules; these functions reach them without making those modules
//! public, and each one runs every consumer of the same untrusted bytes
//! so a target covers the whole path a hostile message or command takes.

/// IMAP command line: the literal announcement the connection loop reads
/// before anything else, then the command parser.
pub fn imap_command_line(line: &str) {
	if let Some(literal) = crate::imap::command::literal_announcement_in_line(line) {
		std::hint::black_box(literal.size);
	}
	let _ = crate::imap::command::parse(line, crate::imap::command::DEFAULT_APPEND_LIMIT);
}

/// DKIM-Signature header value: the tag-list parser (`b=`, `bh=`, `h=`
/// and the rest) and the header canonicalisation it feeds.
pub fn dkim_signature(value: &str) {
	let _ = crate::dkim::signature::parse(value);
	std::hint::black_box(crate::dkim::canon::header(
		crate::dkim::signature::Canon::Relaxed,
		"DKIM-Signature",
		value,
	));
}

/// A whole message through every MIME consumer: IMAP BODYSTRUCTURE and
/// ENVELOPE, JMAP body properties, the DMARC and TLS-RPT report walkers,
/// the From field DMARC and submission read, and DKIM body hashing.
pub fn mime(raw: &[u8]) {
	std::hint::black_box(crate::imap::fetch::render_for_fuzzing(raw));
	std::hint::black_box(crate::api::jmap::email_body_for_fuzzing(raw));
	for kind in [crate::reports::Kind::Dmarc, crate::reports::Kind::TlsRpt] {
		let _ = crate::reports::mime::find_report_part(raw, kind);
	}
	std::hint::black_box(crate::dmarc::author::author(raw));
	std::hint::black_box(crate::dmarc::from_domain(raw));
	std::hint::black_box(crate::dkim::canon::body(
		crate::dkim::signature::Canon::Relaxed,
		raw,
	));
}

mod scram_client;

/// The most bytes an input of the targets below is given: they read network
/// bodies and headers, which the listeners bound well under this.
const INPUT_CAP: usize = 64 * 1024;

/// Attachment content sniffing: the real type of the bytes of an attachment,
/// which the antispam rules and the attachment policy read.
pub fn attachment_inspect(content: &[u8]) {
	let content = &content[..content.len().min(INPUT_CAP)];
	let real = crate::antispam::attachments::sniff::sniff(content);
	std::hint::black_box((
		real.as_str(),
		real.is_executable(),
		real.is_image(),
		real.is_binary(),
	));
}

/// A CalDAV or CardDAV query body, the iCalendar and vCard text it is matched
/// against, and the recurrence rule that expands an event: the XML filter
/// parser, the component walker and the bounded RRULE expansion.
pub fn webdav_filter_rrule(input: &str) {
	let input = &input[..floor_char_boundary(input, INPUT_CAP)];
	if let Ok(filter) = crate::webdav::caldav_filter::parse(input) {
		let _ = std::hint::black_box(crate::webdav::caldav_filter::matches(&filter, input));
	}
	if let Ok(filter) = crate::webdav::carddav_filter::parse(input) {
		std::hint::black_box(crate::webdav::carddav_filter::matches(&filter, input));
	}
	std::hint::black_box(crate::webdav::rrule::parse_datetime(input));
	if let Some(rule) = crate::webdav::rrule::parse_rule(input) {
		std::hint::black_box(crate::webdav::rrule::expand_bounded(
			0,
			Some(&rule),
			0,
			4_000_000_000,
			1_000,
		));
	}
}

/// The ARC header fields: the message signature, the seal, the chain
/// validation keyword and a tag lookup.
pub fn arc_headers(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	let text = String::from_utf8_lossy(raw);
	let _ = crate::arc::signature::parse_message_signature(&text);
	let _ = crate::arc::signature::parse_seal(&text);
	std::hint::black_box(crate::arc::chain::ChainValidation::parse(&text));
	std::hint::black_box(crate::arc::chain::tag(&text, "cv"));
}

/// A JWT as an identity provider would present it: the three parts, the
/// header and the payload decoding and the claim checks. The key is fixed and
/// does not match, so a signature never verifies and every path before that
/// check is the one that runs.
pub fn jwt_decode(token: &str) {
	let token = &token[..floor_char_boundary(token, INPUT_CAP)];
	let validation = crate::jwt::Validation {
		now: 1_800_000_000,
		issuer: Some("https://issuer.example"),
		audience: Some("epistle"),
	};
	for algorithm in [crate::jwt::Algorithm::Rs256, crate::jwt::Algorithm::Es256] {
		let _ = crate::jwt::validate(token, algorithm, &[0u8; 32], &validation);
	}
}

/// The reply of a remote SMTP server as the outbound client frames it: where
/// the first complete reply ends, for any bytes a hostile server sends.
pub fn smtp_reply(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	std::hint::black_box(crate::queue::client::complete_reply_for_fuzzing(raw));
}

/// The records a sending domain publishes and the server reads before it
/// delivers: the MTA-STS policy file, the TLS-RPT record and a TLSA record in
/// its presentation form.
pub fn dns_security_records(text: &str) {
	let text = &text[..floor_char_boundary(text, INPUT_CAP)];
	let _ = crate::mtasts::parse_policy(text);
	std::hint::black_box(crate::tlsrpt::parse(text));
	std::hint::black_box(crate::dane::tlsa::TlsaRecord::parse_presentation(text));
}

/// A DMARC or TLS-RPT report as a remote reporter sends it: the XML and the
/// JSON parsers and the three ways an attachment is unpacked.
pub fn report_payload(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	let _ = crate::reports::dmarc::parse(raw);
	let _ = crate::reports::tlsrpt::parse(raw);
	for encoding in [
		crate::reports::Encoding::Gzip,
		crate::reports::Encoding::Zip,
		crate::reports::Encoding::Uncompressed,
	] {
		let _ = crate::reports::inflate_attachment(raw, encoding);
	}
}

/// Delivery rules matched against a message: the header block is read,
/// unfolded and searched for any bytes a sender puts in it.
pub fn rules_match(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	let rules = [
		crate::rules::Rule {
			sender_domain: None,
			header: Some("Subject".into()),
			header_contains: Some("a".into()),
			junk: true,
			mailbox: None,
		},
		crate::rules::Rule {
			sender_domain: Some("example.org".into()),
			header: Some("List-Id".into()),
			header_contains: Some("list".into()),
			junk: false,
			mailbox: Some("Lists".into()),
		},
	];
	std::hint::black_box(crate::rules::evaluate(&rules, raw, Some("example.org")));
}

/// The responses a source server sends to `migrate imap`, read with the
/// bounded reader and handed to every parser the client calls: status lines
/// and response codes, CAPABILITY, LIST, NAMESPACE and FETCH. The source may
/// be compromised, or impersonated when the run skips certificate checks.
pub fn migrate_imap_response(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	crate::migrate::imap::fuzzing::responses_for_fuzzing(raw);
}

/// A backup archive as `epistle restore` reads it from an operator: the
/// bounded gunzip, the tar reader and the check that decides where each
/// member is written, plus a write and read back of what was read.
pub fn backup_tar(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	crate::cli::backup::fuzzing::archive_for_fuzzing(raw);
}

/// A CalDAV or CardDAV request body outside the filters: the hrefs of a
/// multiget, the discovery and data checks, and a `sync-collection` request
/// with its level, its token and the change log the token is checked against.
pub fn webdav_report_body(input: &str) {
	let input = &input[..floor_char_boundary(input, INPUT_CAP)];
	crate::webdav::fuzzing::report_body_for_fuzzing(input);
}

/// An ARF feedback report as a remote feedback loop sends it, and the report
/// built from the sender and source IP such a complaint carries.
pub fn arf_report(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	crate::antispam::arf::fuzzing::report_for_fuzzing(raw);
}

/// Decoded bytes one walk of [`attachment_walk`] may spend: several times the
/// input, so nested encodings are followed rather than cut at once.
const WALK_DECODED: usize = 4 * INPUT_CAP;

/// A whole message through the attachment inspection: the MIME walk the rules
/// read and the one the text reader takes, the zip and OLE2 directory readers
/// on every part they hand over and on the bytes themselves, and the complete
/// inspection that joins them. A walk keeps to its depth and part limits, and
/// a listing to its entry cap, whatever the message claims.
pub fn attachment_walk(raw: &[u8]) {
	use crate::antispam::attachments::{self, walk};
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	let limits = walk::Limits {
		max_depth: attachments::MAX_DEPTH,
		max_parts: attachments::MAX_PARTS,
		max_decoded: WALK_DECODED,
		deadline: None,
	};
	let visit = |leaf: walk::Leaf| {
		// A uuencoded file inside a text part sits one level below it.
		assert!(
			leaf.depth <= limits.max_depth + 1,
			"leaf at depth {}",
			leaf.depth
		);
		directories(&leaf.content);
		for alternate in &leaf.alternates {
			directories(alternate);
		}
	};
	for walked in [
		walk::walk(raw, &limits, visit),
		walk::walk_text(raw, &limits, visit),
	] {
		// The part that goes past the limit is counted, then the walk stops.
		assert!(
			walked.parts <= limits.max_parts + 1,
			"{} parts",
			walked.parts
		);
		if walked.parts > limits.max_parts {
			assert_eq!(walked.stopped, Some(walk::Stop::TooManyParts));
		}
	}
	directories(raw);
	let report = attachments::inspect(
		raw,
		&attachments::rules::Extensions::default(),
		attachments::Budget::bytes(WALK_DECODED),
	);
	std::hint::black_box(report.reasons());
}

/// The zip and OLE2 directory readers over one buffer.
fn directories(bytes: &[u8]) {
	use crate::antispam::attachments::archive;
	let listing = archive::list_zip(bytes);
	assert!(listing.names.len() <= archive::MAX_ENTRIES);
	std::hint::black_box((
		archive::has_end_record(bytes),
		archive::is_ooxml(&listing),
		archive::ooxml_has_macros(&listing),
	));
	let ole = archive::inspect_ole2(bytes);
	assert_eq!(ole.macros, archive::ole2_has_macros(bytes));
}

/// The records a sender publishes for the checks on inbound mail: an SPF
/// record, a DMARC record and a DKIM key record, read from the same text.
/// The first line is the envelope sender and the second the HELO name, cut to
/// an SMTP command line: the SPF macros expand both, so the local part is the
/// attacker's too. Every domain an SPF record names is expanded, as the
/// evaluator does before it looks the name up.
pub fn sender_auth_records(input: &str) {
	let input = &input[..floor_char_boundary(input, INPUT_CAP)];
	let mut lines = input.splitn(3, '\n');
	let sender = smtp_line(lines.next().unwrap_or(""));
	let helo = smtp_line(lines.next().unwrap_or(""));
	let record = lines.next().unwrap_or("");
	if let Ok(spf) = crate::spf::record::parse(record) {
		for (_, mechanism) in &spf.directives {
			use crate::spf::record::Mechanism;
			match mechanism {
				Mechanism::Ip4 { prefix, .. } => assert!(*prefix <= 32, "ip4 prefix /{prefix}"),
				Mechanism::Ip6 { prefix, .. } => assert!(*prefix <= 128, "ip6 prefix /{prefix}"),
				Mechanism::A {
					domain,
					prefix4,
					prefix6,
				}
				| Mechanism::Mx {
					domain,
					prefix4,
					prefix6,
				} => {
					assert!(*prefix4 <= 32 && *prefix6 <= 128, "/{prefix4} //{prefix6}");
					spf_names(domain.as_deref().unwrap_or(SENDER_DOMAIN), sender, helo);
				}
				Mechanism::Include { domain } | Mechanism::Exists { domain } => {
					spf_names(domain, sender, helo);
				}
				Mechanism::Ptr { domain } => {
					spf_names(domain.as_deref().unwrap_or(SENDER_DOMAIN), sender, helo);
				}
				Mechanism::All => {}
			}
		}
		if let Some(redirect) = &spf.redirect {
			spf_names(redirect, sender, helo);
		}
	}
	spf_names(record, sender, helo);
	if let Some(Ok(dmarc)) = crate::dmarc::record::parse(record) {
		assert!(dmarc.pct <= 100, "pct={}", dmarc.pct);
		assert!(dmarc.rua.iter().all(|uri| !uri.is_empty()));
	}
	if let Some(key) = crate::dkim::key_record::parse(record) {
		use crate::dkim::key_record::KeyType;
		match key.key_type {
			KeyType::Ed25519 => assert_eq!(key.public_key.len(), 32),
			KeyType::Rsa => assert_eq!(key.public_key.first(), Some(&0x30)),
		}
		std::hint::black_box(key.accepts_identity(Some(sender), SENDER_DOMAIN));
		assert!(crate::dkim::key_record::same_usable_key(record, record));
	}
	for algorithm in [
		crate::dkim::signature::Algorithm::RsaSha256,
		crate::dkim::signature::Algorithm::Ed25519Sha256,
	] {
		let found = crate::dkim::key_record::select(&[record.to_string()], algorithm);
		assert!(found.is_none_or(|key| key.fits(algorithm)));
	}
}

/// The domain the SPF and DKIM checks of [`sender_auth_records`] run for.
const SENDER_DOMAIN: &str = "example.org";

/// `line` cut where an SMTP command line ends.
fn smtp_line(line: &str) -> &str {
	&line[..floor_char_boundary(line, crate::smtp::command::MAX_COMMAND_LINE)]
}

/// The name an SPF domain spec expands to for a client on each address
/// family. A spec without a macro expands to itself.
fn spf_names(spec: &str, sender: &str, helo: &str) {
	for ip in [
		std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
		std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
	] {
		let name = crate::spf::expand_macro(spec, ip, SENDER_DOMAIN, sender, helo);
		if !spec.contains('%') {
			assert_eq!(name.as_deref().ok(), Some(spec));
		}
		std::hint::black_box(name.map(|name| name.len()).ok());
	}
}

/// The SASL messages a client sends before it is logged in: PLAIN, the
/// OAUTHBEARER and XOAUTH2 initial response of SMTP and of IMAP, and a
/// SCRAM-SHA-256 exchange under each channel binding policy. The first line is
/// the client-first message and the rest the client-final one.
///
/// The account is made once per process from random bytes. Besides the
/// client's own final message, the exchange is finished the way a client that
/// knows the password would: it must succeed with the nonce the server sent,
/// and fail with any other nonce or a proof that is off by one bit. A final
/// message the server accepts must carry the proof only the password gives.
pub fn sasl_exchange(input: &str) {
	use crate::smtp::scram::{ChannelBinding, ScramError, ScramServer, username_of};
	let input = &input[..floor_char_boundary(input, INPUT_CAP)];
	let _ = crate::smtp::auth::parse_plain(input);
	std::hint::black_box(crate::smtp::session::parse_bearer(input));
	std::hint::black_box(crate::imap::session::parse_bearer(input));
	let (first, last) = input.split_once('\n').unwrap_or((input, ""));
	let account = scram_client::account();
	let username = username_of(first);
	for binding in [
		ChannelBinding::Unsupported,
		ChannelBinding::Supported,
		ChannelBinding::Required(account.end_point.clone()),
	] {
		let mut server =
			ScramServer::new(account.nonce.as_str()).with_channel_binding(binding.clone());
		let Ok((user, server_first)) = server.first(first, &account.credentials) else {
			continue;
		};
		assert_eq!(Some(user), username, "first and username_of disagree");
		let flag = first.split(',').next().unwrap_or("");
		match &binding {
			ChannelBinding::Supported => assert_eq!(flag, "n"),
			ChannelBinding::Required(_) => assert_eq!(flag, "p=tls-server-end-point"),
			ChannelBinding::Unsupported => {}
		}
		let exchange = scram_client::Exchange::new(account, first, &server_first, &binding);
		if let Ok(server_final) = server.finish(last, &account.credentials) {
			let proof = last.split(',').find_map(|field| field.strip_prefix("p="));
			let without_proof = last.rsplit_once(",p=").map(|(head, _)| head);
			let expected = without_proof.map(|head| exchange.proof(head));
			// The assertions name what failed and print no proof or key.
			assert!(
				proof.map(str::to_string) == expected,
				"a proof nobody signed was accepted"
			);
			assert!(
				server_final == exchange.server_final(without_proof.unwrap_or("")),
				"the server signature is not the one its key gives"
			);
		}
		let Some(combined) = server_first
			.strip_prefix("r=")
			.and_then(|rest| rest.split(',').next())
		else {
			panic!("server-first does not open with the nonce");
		};
		let honest = exchange.without_proof(combined);
		assert!(
			server.finish(&exchange.signed(&honest), &account.credentials)
				== Ok(exchange.server_final(&honest)),
			"the password did not open the account",
		);
		let tampered = format!("{honest},p={}", exchange.flipped(&honest));
		assert!(
			server.finish(&tampered, &account.credentials) == Err(ScramError::AuthenticationFailed),
			"a proof off by one bit was accepted",
		);
		if let Some(echoed) = last.split(',').next()
			&& echoed != combined
		{
			let replayed = exchange.without_proof(echoed);
			assert!(
				server.finish(&exchange.signed(&replayed), &account.credentials)
					== Err(ScramError::Malformed),
				"a nonce the server did not send was accepted",
			);
		}
	}
}

/// The largest index at most `max` that is a character boundary of `text`.
fn floor_char_boundary(text: &str, max: usize) -> usize {
	let mut end = max.min(text.len());
	while !text.is_char_boundary(end) {
		end -= 1;
	}
	end
}

/// The secret every run signs SRS addresses with. It is fixed, so a crash
/// reproduces, and it protects nothing: the addresses it signs are never
/// sent anywhere.
const SRS_SECRET: &[u8] = b"epistle-fuzz-srs-secret";

/// The day the SRS addresses of a run pretend it is. The timestamp of an
/// address wraps every 1024 days, so a fixed day keeps every run on the
/// same timestamp and the addresses of a run compare with each other.
const SRS_DAY: u64 = 19_000;

/// The domain the SRS addresses of a run are for.
const SRS_RELAY: &str = "relay.example";

/// The local part of an address the rewriter signed.
fn srs_local_part(address: &str) -> &str {
	match address.strip_suffix(SRS_RELAY) {
		Some(local) => local.strip_suffix('@').unwrap_or(local),
		None => address,
	}
}

/// The same local part with its prefix in lower case. The prefix is matched
/// without regard to case, so the rewriter takes it for the same address.
fn srs_lower_prefix(local_part: &str) -> String {
	match local_part.strip_prefix("SRS0") {
		Some(rest) => format!("srs0{rest}"),
		None => local_part.to_string(),
	}
}

/// The SRS rewriter, driven by what a client sent: an address to reverse and
/// a sender to sign and reverse again.
///
/// `sent` is the local part of an address a client sent, `local` and
/// `domain` the sender a run makes up, and `hosted` the domain an address
/// names. Every address is reversed twice, plain and naming a hosted
/// domain, and the sender is signed and reversed again twice.
///
/// # Panics
///
/// When the rewriter reverses an address to a pair it would not sign again,
/// or when an address it signs does not reverse to the pair it hides. Both
/// are the same defect seen from its two ends.
pub fn srs_reverse(sent: &str, local: &str, domain: &str, hosted: &str) {
	let srs = crate::queue::srs::Srs::new(SRS_SECRET);
	for hosted_domain in [None, Some(hosted)] {
		let reversed = match hosted_domain {
			Some(name) => srs.reverse_for(name, sent, SRS_DAY, 0),
			None => srs.reverse(sent, SRS_DAY, 0),
		};
		let Some((local, domain)) = reversed else {
			continue;
		};
		// The address the rewriter signs for the pair it gave back must be
		// the address it reversed. The prefix is matched without regard to
		// case, and the timestamp with it, so the two may differ in the
		// case of the prefix alone.
		let signed = match hosted_domain {
			Some(name) => {
				srs.forward_for(name, (local.as_str(), domain.as_str()), SRS_RELAY, SRS_DAY)
			}
			None => srs.forward(local.as_str(), domain.as_str(), SRS_RELAY, SRS_DAY),
		};
		assert!(
			srs_local_part(&signed).eq_ignore_ascii_case(sent),
			"the rewriter does not sign the pair it gave back: {signed}"
		);
	}
	for hosted_domain in [None, Some(hosted)] {
		let signed = match hosted_domain {
			Some(name) => srs.forward_for(name, (local, domain), SRS_RELAY, SRS_DAY),
			None => srs.forward(local, domain, SRS_RELAY, SRS_DAY),
		};
		let signed_local = srs_local_part(&signed);
		let reversed = match hosted_domain {
			Some(name) => srs.reverse_for(name, signed_local, SRS_DAY, 0),
			None => srs.reverse(signed_local, SRS_DAY, 0),
		};
		assert_eq!(
			reversed,
			Some((local.to_string(), domain.to_string())),
			"the rewriter does not reverse the pair it signed"
		);
		// The prefix in lower case names the same address, and the pair
		// behind it is the same one.
		let lowered = srs_lower_prefix(signed_local);
		let reversed = match hosted_domain {
			Some(name) => srs.reverse_for(name, &lowered, SRS_DAY, 0),
			None => srs.reverse(&lowered, SRS_DAY, 0),
		};
		assert_eq!(
			reversed,
			Some((local.to_string(), domain.to_string())),
			"the rewriter does not reverse the pair it signed"
		);
	}
}

/// The message size limit of a BDAT run: small, so the oversize path is
/// reachable from short inputs.
const BDAT_MAX_SIZE: usize = 256;

/// A BDAT chunked message as a client sends it, read through the SMTP
/// session: the chunks of the message, and the flag that marks the last
/// one.
///
/// The session is the one a client talks to: it answers the commands, reads
/// the chunks and hands the message over. The `directory` resolves the
/// recipients, `sender` and `recipient` are the envelope the client names,
/// and every chunk is one the client sends, with the flag that says whether
/// it is the last one.
///
/// # Panics
///
/// When the sequence hands over more than one message, or a message whose
/// body is not the octets of the chunks that were sent.
pub fn smtp_bdat(
	directory: std::sync::Arc<crate::smtp::directory::Directory>,
	sender: &str,
	recipient: &str,
	chunks: &[(Vec<u8>, bool)],
) {
	use crate::smtp::session::{Action, Session};

	let mut session = Session::new("mx.example.org")
		.with_directory(directory)
		.with_max_message_size(BDAT_MAX_SIZE);
	session.greeting();
	session.command_line("EHLO client.test");
	session.command_line(&format!("MAIL FROM:<{sender}>"));
	session.command_line(&format!("RCPT TO:<{recipient}>"));
	// The octets the session kept, and the messages it handed over.
	let mut body: Vec<u8> = Vec::new();
	let mut delivered = 0usize;
	for (chunk, last) in chunks {
		let line = format!("BDAT {}{}", chunk.len(), if *last { " LAST" } else { "" });
		match session.command_line(&line) {
			Action::CollectChunk { size, last } => {
				let bytes = &chunk[..size.min(chunk.len())];
				match session.bdat_chunk(bytes, last) {
					Action::Deliver(_, message) => {
						delivered += 1;
						assert_eq!(delivered, 1, "more than one message in a chunk sequence");
						body.extend_from_slice(bytes);
						assert_eq!(
							message.data, body,
							"the message is not the chunks that were sent"
						);
						assert_eq!(
							message.reverse_path, sender,
							"the sender is not the one sent"
						);
						assert_eq!(
							message.recipients.len(),
							1,
							"the message has other recipients"
						);
						assert!(
							message.recipients[0].eq_ignore_ascii_case(recipient),
							"the recipient is not the one sent"
						);
					}
					// The chunk was kept.
					Action::Continue(reply) if reply.code() == 250 => {
						body.extend_from_slice(bytes);
					}
					// A refused chunk ends the transaction, and the body it
					// had goes back with it.
					Action::Continue(_) => body.clear(),
					// The connection is over.
					Action::Close(_) => break,
					_ => {}
				}
			}
			// A refused chunk is read and thrown away.
			Action::DiscardChunk { .. } => body.clear(),
			// The connection is over.
			Action::Close(_) => break,
			_ => {}
		}
	}
}
