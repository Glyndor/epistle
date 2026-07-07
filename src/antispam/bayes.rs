//! Bayesian content classification (Graham's "A Plan for Spam").
//!
//! This module is the pure core: tokenization and probability math. The token
//! corpus (per-token ham/spam counts) is stored and trained elsewhere; here we
//! only turn counts into a spam probability for a message. Keeping it pure
//! makes the classifier fully unit-testable without a database.

use std::collections::HashSet;

/// Minimum and maximum token length kept during tokenization.
const MIN_TOKEN_LEN: usize = 2;
const MAX_TOKEN_LEN: usize = 30;

/// How many of the most-interesting tokens feed the combined score.
const SIGNIFICANT_TOKENS: usize = 15;

/// Ham/spam occurrence counts for one token across the trained corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TokenCounts {
	pub ham: u64,
	pub spam: u64,
}

/// Message totals of the trained corpus, used to normalize token counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Corpus {
	pub ham_messages: u64,
	pub spam_messages: u64,
}

/// Split text into lowercased, deduplicated tokens. Tokens are alphanumeric
/// runs within a length band; counting a token once per message matches
/// Graham's training model.
pub fn tokenize(text: &str) -> Vec<String> {
	let mut seen = HashSet::new();
	let mut tokens = Vec::new();
	for raw in text.split(|c: char| !c.is_alphanumeric()) {
		if (MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&raw.len()) {
			let token = raw.to_ascii_lowercase();
			if seen.insert(token.clone()) {
				tokens.push(token);
			}
		}
	}
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
