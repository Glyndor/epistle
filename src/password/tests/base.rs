	use super::*;
	use crate::test_fixtures as fixtures;

	#[test]
	fn accepts_a_strong_in_range_ascii_password() {
		// Runtime credentials must pass the same policy as real account passwords.
		assert_eq!(validate(fixtures::password()), Ok(()));
	}

	#[test]
	fn accepts_the_length_boundaries() {
		let min = fixtures::printable_ascii(MIN_LENGTH);
		assert_eq!(min.chars().count(), MIN_LENGTH);
		assert_eq!(validate(&min), Ok(()));
		let max = fixtures::printable_ascii(MAX_LENGTH);
		assert_eq!(max.chars().count(), MAX_LENGTH);
		assert_eq!(validate(&max), Ok(()));
	}

	#[test]
	fn rejects_one_character_below_the_minimum() {
		let short = fixtures::printable_ascii(MIN_LENGTH - 1);
		assert_eq!(short.chars().count(), 11);
		assert_eq!(validate(&short), Err(Rejection::TooShort));
		let empty = fixtures::printable_ascii(0);
		assert!(empty.is_empty(), "shape precondition");
		assert_eq!(validate(&empty), Err(Rejection::TooShort));
	}

	#[test]
	fn rejects_one_character_above_the_maximum() {
		let long = fixtures::printable_ascii(MAX_LENGTH + 1);
		assert_eq!(long.chars().count(), 65);
		assert_eq!(validate(&long), Err(Rejection::TooLong));
	}

	#[test]
	fn rejects_a_non_ascii_character_anywhere_in_range() {
		for len in [MIN_LENGTH, MIN_LENGTH + 1, MAX_LENGTH - 1, MAX_LENGTH] {
			let text = fixtures::printable_ascii_with(fixtures::non_ascii_char(), len);
			assert_eq!(text.chars().count(), len, "length precondition");
			assert!(!text.is_ascii(), "shape precondition");
			assert_eq!(
				validate(&text),
				Err(Rejection::IllegalCharacter),
				"len {len}"
			);
		}
	}

	#[test]
	fn rejects_a_string_made_only_of_non_ascii_characters() {
		let text: String = (0..MIN_LENGTH)
			.map(|_| fixtures::non_ascii_char())
			.collect();
		assert_eq!(text.chars().count(), MIN_LENGTH);
		assert!(text.chars().all(|c| !c.is_ascii()), "shape precondition");
		assert_eq!(validate(&text), Err(Rejection::IllegalCharacter));
	}

	#[test]
	fn length_is_counted_in_characters_not_bytes() {
		// MAX_LENGTH multibyte characters are far more than MAX_LENGTH bytes,
		// yet the length check passes and the character set is what rejects.
		let text: String = (0..MAX_LENGTH)
			.map(|_| fixtures::non_ascii_char())
			.collect();
		assert_eq!(text.chars().count(), MAX_LENGTH);
		assert!(text.len() > MAX_LENGTH, "shape precondition");
		assert_eq!(validate(&text), Err(Rejection::IllegalCharacter));
	}

	#[test]
	fn rejects_every_control_character_anywhere_in_range() {
		let controls = fixtures::control_chars();
		assert_eq!(controls.len(), 33, "C0 controls plus DEL");
		for control in controls {
			let text = fixtures::printable_ascii_with(control, MIN_LENGTH + 1);
			assert_eq!(text.chars().count(), MIN_LENGTH + 1, "length precondition");
			assert_eq!(
				validate(&text),
				Err(Rejection::IllegalCharacter),
				"control U+{:04X}",
				u32::from(control)
			);
		}
	}

	#[test]
	fn rejects_every_bundled_breached_entry() {
		assert!(!breached_set().is_empty(), "the bundled list is not empty");
		for entry in breached_set() {
			assert_eq!(
				validate(entry),
				Err(Rejection::Breached),
				"bundled entry of {} characters",
				entry.chars().count()
			);
		}
	}

	#[test]
	fn every_bundled_entry_would_survive_the_earlier_checks() {
		// The breach list is only meaningful for entries that pass length and
		// character-set — otherwise they can never reach the lookup.
		for entry in breached_set() {
			let length = entry.chars().count();
			assert!(
				(MIN_LENGTH..=MAX_LENGTH).contains(&length),
				"breached entry {entry:?} is out of the length window"
			);
			assert!(
				entry.bytes().all(|b| (0x20..=0x7E).contains(&b)),
				"breached entry {entry:?} is not printable ASCII"
			);
		}
	}

	/// Entries of the bundled top-100k file, without its comment header.
	fn top100k_entries() -> impl Iterator<Item = &'static str> {
		super::BREACHED_RAW_TOP100K
			.lines()
			.map(str::trim)
			.filter(|line| !line.is_empty() && !line.starts_with('#'))
	}

	#[test]
	fn the_top100k_file_ships_only_entries_the_lookup_can_reach() {
		// The file is filtered when it is imported. An unfiltered paste would
		// add close to a megabyte of entries that can never be looked up.
		let mut count = 0;
		for entry in top100k_entries() {
			count += 1;
			assert!(
				survives_filter(entry),
				"entry {entry:?} can never reach the lookup"
			);
		}
		assert!(count > 1000, "only {count} entries in the top-100k file");
	}

	#[test]
	fn every_top100k_entry_is_refused_as_breached() {
		for entry in top100k_entries() {
			assert_eq!(validate(entry), Err(Rejection::Breached), "{entry:?}");
		}
	}

	#[test]
	fn a_known_entry_lookup_is_case_insensitive() {
		// Digits have no case, so pick an entry with a letter in it.
		let entry = top100k_entries()
			.find(|entry| entry.bytes().any(|b| b.is_ascii_lowercase()))
			.expect("the list has an entry with a lowercase letter");
		let upper = entry.to_ascii_uppercase();
		assert_ne!(upper, entry, "shape precondition: uppercasing changed it");
		assert_eq!(validate(&upper), Err(Rejection::Breached), "{upper:?}");
	}

	#[test]
	fn a_fresh_random_password_still_passes_with_the_real_list() {
		// The bundled 100k list is bigger by a wide margin; this exercises a
		// strong random credential (URL-safe base64, all printable ASCII) so
		// the breach check is run against the bundled set on a value that
		// cannot be in it.
		let password = fixtures::printable_ascii(MIN_LENGTH + 8);
		assert!(
			!breached_set().contains(password.as_str()),
			"shape precondition: a freshly-generated password must not be in the bundle"
		);
		assert_eq!(validate(&password), Ok(()));
	}

	#[test]
	fn the_bundled_lookup_set_covers_more_than_five_hundred_entries() {
		// Anything under a few hundred would mean the bundle has stopped
		// being effective.
		assert!(
			breached_set().len() > 500,
			"bundled lookup set is {} entries, expected a substantial list",
			breached_set().len(),
		);
	}
