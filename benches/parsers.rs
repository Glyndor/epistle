//! Microbenchmarks for the hot-path parsers: SMTP and IMAP command parsing,
//! address parsing, and the line decoder. These are the per-byte/per-command
//! paths every connection exercises, so they are the first place to watch for
//! regressions (`cargo bench`).

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use epistle::imap::command::parse as imap_parse;
use epistle::imap::mailbox::{Flag, render_flags};
use epistle::smtp::address::Address;
use epistle::smtp::command::parse as smtp_parse;
use epistle::smtp::line::LineDecoder;

fn smtp_command(c: &mut Criterion) {
	c.bench_function("smtp_parse_mail_from", |b| {
		b.iter(|| {
			smtp_parse(black_box(
				"MAIL FROM:<alice@example.org> SIZE=1000 BODY=8BITMIME",
			))
		})
	});
	c.bench_function("smtp_parse_rcpt_to", |b| {
		b.iter(|| {
			smtp_parse(black_box(
				"RCPT TO:<bob@example.org> NOTIFY=SUCCESS,FAILURE",
			))
		})
	});
}

fn address(c: &mut Criterion) {
	c.bench_function("address_parse", |b| {
		b.iter(|| Address::parse(black_box("user.name+tag@sub.example.org")))
	});
}

fn imap_command(c: &mut Criterion) {
	c.bench_function("imap_parse_fetch", |b| {
		b.iter(|| {
			imap_parse(black_box(
				"a1 UID FETCH 1:* (FLAGS BODY[HEADER.FIELDS (FROM TO)])",
			))
		})
	});
	c.bench_function("imap_parse_search", |b| {
		b.iter(|| imap_parse(black_box("a2 SEARCH OR FROM alice SINCE 1-Jan-2026 UNSEEN")))
	});
}

fn line_decoder(c: &mut Criterion) {
	// A burst of pipelined commands, decoded line by line.
	let input = b"EHLO client.example.org\r\nMAIL FROM:<a@example.org>\r\nRCPT TO:<b@example.org>\r\nDATA\r\n";
	c.bench_function("line_decoder_burst", |b| {
		b.iter(|| {
			let mut decoder = LineDecoder::new();
			decoder.feed(black_box(input));
			while let Ok(Some(line)) = decoder.next_line() {
				black_box(line);
			}
		})
	});
}

fn render(c: &mut Criterion) {
	// Rendered once per message in every FETCH FLAGS / STORE response, so a
	// representative multi-flag set is the case to watch.
	let flags = [Flag::Seen, Flag::Answered, Flag::Flagged];
	c.bench_function("render_flags", |b| {
		b.iter(|| black_box(render_flags(black_box(&flags))))
	});
}

criterion_group!(
	benches,
	smtp_command,
	address,
	imap_command,
	line_decoder,
	render
);
criterion_main!(benches);
