use super::*;

#[test]
fn tokenize_lowercases_dedups_and_bands() {
	let tokens = tokenize("Hello hello WORLD a verylongtokenthatexceedsthirtycharacterslimit!! 42");
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
