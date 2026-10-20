//! Bayesian content classification (Graham's "A Plan for Spam").
//!
//! This module is the pure core: tokenization and probability math. The token
//! corpus (per-token ham/spam counts) is stored and trained elsewhere; here we
//! only turn counts into a spam probability for a message. Keeping it pure
//! makes the classifier fully unit-testable without a database.

use std::collections::{BinaryHeap, HashSet};

/// Minimum and maximum token length kept during tokenization.
const MIN_TOKEN_LEN: usize = 2;
const MAX_TOKEN_LEN: usize = 30;

/// How many of the most-interesting tokens feed the combined score.
const SIGNIFICANT_TOKENS: usize = 15;

/// Ham/spam occurrence counts for one token across the trained corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TokenCounts {
	/// Number of distinct ham messages in which the token appeared at least
	/// once during training.
	pub ham: u64,
	/// Number of distinct spam messages in which the token appeared at least
	/// once during training.
	pub spam: u64,
}

/// Message totals of the trained corpus, used to normalize token counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Corpus {
	/// Total ham messages the corpus was trained on. Floored at 1 inside
	/// `token_probability` so a fresh corpus cannot divide by zero.
	pub ham_messages: u64,
	/// Total spam messages the corpus was trained on. Floored at 1 inside
	/// `token_probability` so a fresh corpus cannot divide by zero.
	pub spam_messages: u64,
}

/// Split text into lowercased, deduplicated tokens. Tokens are alphanumeric
/// runs within a length band; counting a token once per message matches
/// Graham's training model.
pub fn tokenize(text: &str) -> Vec<String> {
	tokenize_bounded(text, usize::MAX)
}

/// [`tokenize`] that stops after `max_tokens` distinct tokens, in order of
/// appearance. The scan ends there too, so the work and the memory are
/// bounded by `max_tokens` however much text there is, which a trainer fed
/// by remote senders needs.
pub fn tokenize_bounded(text: &str, max_tokens: usize) -> Vec<String> {
	let mut seen = HashSet::new();
	let mut tokens = Vec::new();
	for raw in text.split(|c: char| !c.is_alphanumeric()) {
		if tokens.len() >= max_tokens {
			break;
		}
		if (MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&raw.len()) {
			let token = raw.to_lowercase();
			if seen.insert(token.clone()) {
				tokens.push(token);
			}
		}
	}
	tokens
}

/// A keyed fingerprint of a token, by which [`sample_tokens`] ranks them.
pub type TokenTag = [u8; 32];

/// The `cap` distinct tokens of `text` with the smallest `tag_of`, smallest
/// first.
///
/// This is how a message with more distinct tokens than the cap is cut down.
/// Taking the first ones would let whoever writes the message choose what is
/// looked at by putting filler in front; ranking by a keyed hash of the token
/// leaves no position to exploit, and the selection depends on the set of
/// tokens, not on their order or how often they repeat. The scan keeps `cap`
/// entries at most, however long the text is.
pub fn sample_tokens<F>(text: &str, cap: usize, tag_of: F) -> Vec<String>
where
	F: Fn(&str) -> TokenTag,
{
	sample_tokens_without(text, cap, tag_of, &HashSet::new())
}

/// [`sample_tokens`] that leaves out the tokens in `exclude`, which the
/// caller already has.
pub fn sample_tokens_without<F>(
	text: &str,
	cap: usize,
	tag_of: F,
	exclude: &HashSet<String>,
) -> Vec<String>
where
	F: Fn(&str) -> TokenTag,
{
	if cap == 0 {
		return Vec::new();
	}
	// A max-heap on the tag: the root is the worst token kept so far.
	let mut kept: BinaryHeap<(TokenTag, String)> = BinaryHeap::with_capacity(cap + 1);
	let mut tags: HashSet<TokenTag> = HashSet::with_capacity(cap + 1);
	for raw in text.split(|c: char| !c.is_alphanumeric()) {
		if !(MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&raw.len()) {
			continue;
		}
		let token = raw.to_lowercase();
		if exclude.contains(&token) {
			continue;
		}
		let tag = tag_of(&token);
		if tags.contains(&tag) {
			continue;
		}
		if kept.len() < cap {
			tags.insert(tag);
			kept.push((tag, token));
		} else if kept.peek().is_some_and(|(worst, _)| tag < *worst) {
			if let Some((evicted, _)) = kept.pop() {
				tags.remove(&evicted);
			}
			tags.insert(tag);
			kept.push((tag, token));
		}
	}
	kept.into_sorted_vec()
		.into_iter()
		.map(|(_, token)| token)
		.collect()
}

/// The last `n` distinct tokens of `text`, in order of appearance.
pub fn last_tokens(text: &str, n: usize) -> Vec<String> {
	let mut seen = HashSet::new();
	let mut tokens = Vec::new();
	for raw in text.rsplit(|c: char| !c.is_alphanumeric()) {
		if tokens.len() >= n {
			break;
		}
		if (MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&raw.len()) {
			let token = raw.to_lowercase();
			if seen.insert(token.clone()) {
				tokens.push(token);
			}
		}
	}
	tokens.reverse();
	tokens
}

/// The probability a message is spam given a single token's corpus counts
/// (Graham). Ham counts are doubled to bias against false positives; rare and
/// unseen tokens are pulled toward a neutral 0.4. Result is clamped to
/// `[0.01, 0.99]` so no single token dominates.
pub fn token_probability(counts: TokenCounts, corpus: Corpus) -> f64 {
	// Too little training data for this token: neutral-ish prior.
	if counts.ham + counts.spam < 5 {
		return 0.4;
	}
	let ngood = corpus.ham_messages.max(1) as f64;
	let nbad = corpus.spam_messages.max(1) as f64;
	let g = (2 * counts.ham) as f64 / ngood;
	let b = counts.spam as f64 / nbad;
	let prob = b / (g + b);
	prob.clamp(0.01, 0.99)
}

/// Combine token probabilities into a single spam score in `[0, 1]`, using the
/// `SIGNIFICANT_TOKENS` tokens whose probability is farthest from neutral
/// (Graham's combining rule). With no usable tokens the score is a neutral 0.5.
pub fn classify<F>(tokens: &[String], counts_of: F, corpus: Corpus) -> f64
where
	F: Fn(&str) -> TokenCounts,
{
	let mut probs: Vec<f64> = tokens
		.iter()
		.map(|t| token_probability(counts_of(t), corpus))
		.collect();
	// Most interesting first: largest distance from 0.5.
	probs.sort_by(|a, b| {
		(b - 0.5)
			.abs()
			.partial_cmp(&(a - 0.5).abs())
			.expect("finite probabilities")
	});
	probs.truncate(SIGNIFICANT_TOKENS);
	if probs.is_empty() {
		return 0.5;
	}
	let prod: f64 = probs.iter().product();
	let inv: f64 = probs.iter().map(|p| 1.0 - p).product();
	prod / (prod + inv)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn tokenize_lowercases_dedups_and_bands() {
		let tokens =
			tokenize("Hello hello WORLD a verylongtokenthatexceedsthirtycharacterslimit!! 42");
		assert!(tokens.contains(&"hello".to_string()));
		assert!(tokens.contains(&"world".to_string()));
		assert!(tokens.contains(&"42".to_string()));
		// Deduplicated.
		assert_eq!(tokens.iter().filter(|t| *t == "hello").count(), 1);
		// "a" is below the minimum length; the >30 char run is dropped.
		assert!(!tokens.contains(&"a".to_string()));
		assert!(tokens.iter().all(|t| t.len() <= MAX_TOKEN_LEN));
	}

	#[test]
	fn tokenize_bounded_stops_at_the_cap_and_keeps_the_first_tokens() {
		let tokens = tokenize_bounded("alpha beta alpha gamma delta epsilon", 3);
		assert_eq!(tokens, ["alpha", "beta", "gamma"]);
		assert!(tokenize_bounded("alpha beta", 0).is_empty());
		assert_eq!(
			tokenize_bounded("alpha beta", usize::MAX),
			tokenize("alpha beta")
		);
	}

	/// A stand-in for the keyed hash: stable, and unrelated to the order.
	fn tag(token: &str) -> TokenTag {
		let mut tag = [0u8; 32];
		let mut state = 0xcbf2_9ce4_8422_2325u64;
		for byte in token.bytes() {
			state = (state ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
		}
		for chunk in tag.chunks_mut(8) {
			state = state.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(23);
			chunk.copy_from_slice(&state.to_be_bytes());
		}
		tag
	}

	#[test]
	fn sample_tokens_keeps_the_cap_and_the_smallest_tags() {
		let text: String = (0..500).map(|n| format!("tok{n:04} ")).collect();
		let sample = sample_tokens(&text, 40, tag);
		assert_eq!(sample.len(), 40);
		let mut every: Vec<String> = tokenize(&text);
		every.sort_by_key(|token| tag(token));
		every.truncate(40);
		assert_eq!(sample, every);
		assert!(sample_tokens(&text, 0, tag).is_empty());
		assert_eq!(sample_tokens("alpha beta", 40, tag).len(), 2);
	}

	/// What is looked at cannot be steered by where the words are put, how
	/// often they repeat, or what comes in front of them.
	#[test]
	fn sample_tokens_depends_on_the_set_of_tokens_only() {
		let words: Vec<String> = (0..300).map(|n| format!("tok{n:04}")).collect();
		let forward = words.join(" ");
		let backward = words.iter().rev().cloned().collect::<Vec<_>>().join(" ");
		let repeated = format!("{forward} {forward} {}", words[..50].join(" "));
		let first = sample_tokens(&forward, 25, tag);
		assert_eq!(first, sample_tokens(&backward, 25, tag));
		assert_eq!(first, sample_tokens(&repeated, 25, tag));
		assert_eq!(first, sample_tokens(&forward.to_uppercase(), 25, tag));
	}

	#[test]
	fn last_tokens_are_the_distinct_tail_in_order_of_appearance() {
		assert_eq!(
			last_tokens("one two three two four five", 3),
			["two", "four", "five"].map(String::from)
		);
		assert_eq!(
			last_tokens("alpha beta", 9),
			["alpha", "beta"].map(String::from)
		);
		assert!(last_tokens("alpha", 0).is_empty());
	}

	#[test]
	fn sample_tokens_without_leaves_out_what_the_caller_has() {
		let text: String = (0..200).map(|n| format!("tok{n:04} ")).collect();
		let exclude: HashSet<String> = tokenize(&text).into_iter().take(100).collect();
		let sample = sample_tokens_without(&text, 30, tag, &exclude);
		assert_eq!(sample.len(), 30);
		assert!(sample.iter().all(|token| !exclude.contains(token)));
	}

	/// A word in capitals in an alphabet with two cases is the same word: only
	/// ASCII was folded, so `ПРИВЕТ` and `привет` were two tokens.
	#[test]
	fn letters_outside_ascii_are_folded_too() {
		assert_eq!(tokenize("ПРИВЕТ Привет привет ÑANDÚ"), ["привет", "ñandú"]);
		assert_eq!(tokenize_bounded("ÉCOLE école", 9), ["école"]);
		assert_eq!(last_tokens("ÉCOLE école", 9), ["école"]);
		let tag = |token: &str| {
			let mut tag = [0u8; 32];
			tag[0] = token.len() as u8;
			tag
		};
		assert_eq!(sample_tokens("ÉCOLE école", 9, tag), ["école"]);
	}

	#[test]
	fn token_probability_is_neutral_without_training() {
		let corpus = Corpus {
			ham_messages: 100,
			spam_messages: 100,
		};
		assert_eq!(
			token_probability(TokenCounts { ham: 1, spam: 1 }, corpus),
			0.4
		);
	}

	#[test]
	fn token_probability_clamps_and_orders() {
		let corpus = Corpus {
			ham_messages: 100,
			spam_messages: 100,
		};
		let spammy = token_probability(TokenCounts { ham: 0, spam: 50 }, corpus);
		let hammy = token_probability(TokenCounts { ham: 50, spam: 0 }, corpus);
		assert!((0.9..=0.99).contains(&spammy), "{spammy}");
		assert!((0.01..=0.1).contains(&hammy), "{hammy}");
	}

	#[test]
	fn classify_leans_spam_for_spammy_tokens() {
		let corpus = Corpus {
			ham_messages: 100,
			spam_messages: 100,
		};
		let tokens = vec!["viagra".to_string(), "free".to_string()];
		let score = classify(&tokens, |_| TokenCounts { ham: 0, spam: 40 }, corpus);
		assert!(score > 0.9, "score {score}");
	}

	#[test]
	fn classify_leans_ham_for_hammy_tokens() {
		let corpus = Corpus {
			ham_messages: 100,
			spam_messages: 100,
		};
		let tokens = vec!["invoice".to_string(), "meeting".to_string()];
		let score = classify(&tokens, |_| TokenCounts { ham: 40, spam: 0 }, corpus);
		assert!(score < 0.1, "score {score}");
	}

	#[test]
	fn classify_neutral_without_tokens() {
		let corpus = Corpus {
			ham_messages: 1,
			spam_messages: 1,
		};
		assert_eq!(classify(&[], |_| TokenCounts::default(), corpus), 0.5);
	}
}
