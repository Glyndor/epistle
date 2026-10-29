//! Seeded random scripts against random messages: whatever they hold, a run
//! ends, and what comes out keeps the invariants the limits promise. The
//! same shape as the `sieve_run` fuzz target, with a fixed seed so that it
//! runs in the test suite (the fuzz target is the open-ended version).

use super::super::interp::{Message, Outcome, evaluate};
use super::super::parser::parse;
use super::lexer::tokenize;

/// xorshift64*: enough randomness for generating cases, and reproducible.
struct Rng(u64);

impl Rng {
	fn next(&mut self) -> u64 {
		self.0 ^= self.0 >> 12;
		self.0 ^= self.0 << 25;
		self.0 ^= self.0 >> 27;
		self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
	}

	fn below(&mut self, n: usize) -> usize {
		(self.next() % n as u64) as usize
	}

	fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
		items[self.below(items.len())]
	}
}

const HEADERS: &[&str] = &["subject", "from", "to", "received", "x-a", "list-id"];
const KEYS: &[&str] = &["a", "*", "a*b", "?*?", "*a*a*a*b", "spam", "", "*,*,*,*"];
const TESTS: &[&str] = &[
	"header :contains",
	"header :matches",
	"header :is",
	"address :matches",
	"address :domain :is",
	"envelope :matches",
	"body :contains",
	"body :matches",
];
const ACTIONS: &[&str] = &[
	"keep;",
	"discard;",
	"fileinto \"F{N}\";",
	"fileinto :create \"A/B\";",
	"redirect :copy \"r{N}@y.example\";",
	"redirect :copy \"${0}@y.example\";",
	"fileinto :copy \"G{N}\";",
	"addflag \"f{N}\";",
	"reject \"no ${1}\";",
	"ereject \"no\";",
	"vacation \"away\";",
	"setflag \"a b\";",
	"addflag [\"k1\", \"k2\", \"\\\\Seen\"];",
	"removeflag \"k1\";",
	"set \"v\" \"${v}${v}${1}\";",
	"stop;",
];

fn test(rng: &mut Rng, depth: usize) -> String {
	match rng.below(if depth > 2 { 4 } else { 6 }) {
		4 => format!("not {}", test(rng, depth + 1)),
		5 => format!(
			"{}({}, {})",
			rng.pick(&["allof", "anyof"]),
			test(rng, depth + 1),
			test(rng, depth + 1)
		),
		_ => {
			let name = rng.pick(TESTS);
			let key = rng.pick(KEYS);
			if name.starts_with("body") || name.starts_with("envelope") {
				let part = if name.starts_with("envelope") {
					"\"from\" "
				} else {
					""
				};
				format!("{name} {part}\"{key}\"")
			} else {
				format!("{name} \"{}\" \"{key}\"", rng.pick(HEADERS))
			}
		}
	}
}

fn block(rng: &mut Rng, depth: usize) -> String {
	let mut out = String::new();
	for _ in 0..1 + rng.below(14) {
		if depth < 3 && rng.below(3) == 0 {
			out.push_str(&format!(
				"if {} {{ {} }}\n",
				test(rng, 0),
				block(rng, depth + 1)
			));
		} else {
			let action = rng.pick(ACTIONS);
			out.push_str(&action.replace("{N}", &rng.below(12).to_string()));
			out.push('\n');
		}
	}
	out
}

fn message(rng: &mut Rng) -> Vec<u8> {
	let mut raw = String::new();
	for _ in 0..rng.below(40) {
		let name = rng.pick(HEADERS);
		let width = [0, 3, 50, 5000][rng.below(4)];
		raw.push_str(&format!(
			"{name}: {}{}\r\n",
			rng.pick(KEYS).replace('*', "a"),
			"a".repeat(width)
		));
	}
	raw.push_str("\r\n");
	raw.push_str(&"ab,".repeat(rng.below(40_000)));
	raw.into_bytes()
}

fn holds(outcome: &Outcome) {
	assert!(outcome.redirects.len() <= super::super::interp::MAX_REDIRECTS);
	assert!(outcome.fileinto.len() <= 8);
	assert!(outcome.flags.len() <= super::super::interp::MAX_FLAGS);
	if outcome.aborted {
		assert!(
			outcome.redirects.is_empty() && outcome.reject.is_none() && outcome.vacation.is_none(),
			"an incomplete run sends nothing: {outcome:?}"
		);
	}
	// A message is somewhere: kept, filed, forwarded or deliberately dropped.
	assert!(
		outcome.keep
			|| outcome.discarded
			|| !outcome.fileinto.is_empty()
			|| !outcome.redirects.is_empty()
			|| outcome.reject.is_some(),
		"the message went nowhere: {outcome:?}"
	);
}

#[test]
fn random_scripts_and_messages_end_and_keep_the_limits() {
	let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
	let mut ran = 0;
	for _ in 0..600 {
		let script = format!(
			"require [\"fileinto\", \"envelope\", \"body\", \"variables\", \"reject\", \
			 \"ereject\", \"vacation\", \"imap4flags\", \"copy\", \"mailbox\"];\n{}",
			block(&mut rng, 0)
		);
		let Ok(tokens) = tokenize(&script) else {
			continue;
		};
		let Ok(commands) = parse(&tokens) else {
			continue;
		};
		let parsed = Message::parse(&message(&mut rng)).with_envelope(
			"sender@elsewhere.example".to_string(),
			vec!["a@b.example".to_string()],
		);
		holds(&evaluate(&commands, &parsed));
		ran += 1;
	}
	assert!(ran > 500, "only {ran} of the scripts were valid");
}
