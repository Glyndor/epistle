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
mod tests;
