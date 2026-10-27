use serde_json::Value;

use super::*;
use crate::evidence::rotation::Rotation;

/// How many kinds of break there are. `index_of` is an exhaustive match, so
/// a new kind does not compile until it has an index here and a sample.
const KINDS: usize = 8;

fn index_of(found: &FinalBreak) -> usize {
	match found {
		FinalBreak::Signer { .. } => 0,
		FinalBreak::Switch { .. } => 1,
		FinalBreak::HandOver { .. } => 2,
		FinalBreak::Purge { .. } => 3,
		FinalBreak::AnchorMismatch { .. } => 4,
		FinalBreak::AnchorOrphan { .. } => 5,
		FinalBreak::HeadMissing { .. } => 6,
		FinalBreak::Rollback { .. } => 7,
	}
}

fn hash(n: u8) -> String {
	format!("{n:02x}").repeat(32)
}

fn anchor() -> Anchor {
	Anchor {
		through: "2026-10-14".into(),
		last_hash: hash(1),
		last_seq: 4,
		last_time: 5,
		checkpoint: hash(2),
	}
}

fn purge() -> Purge {
	Purge {
		from: "2026-10-12".into(),
		through: "2026-10-14".into(),
		records: 3,
		last_hash: hash(1),
		checkpoint: hash(2),
		statement: hash(3),
	}
}

fn rotation() -> Rotation {
	Rotation {
		old: hash(4),
		new: hash(5),
		day: "2026-10-17".into(),
		signature: "cd".repeat(64),
	}
}

fn sample_of(index: usize) -> FinalBreak {
	let day = "2026-10-14".to_string();
	match index {
		0 => FinalBreak::Signer {
			day,
			key: hash(4),
			checkpoint: hash(6),
			why: "signed with a key that had already handed over".into(),
			timeline: "[[\"a\"],[]]".into(),
		},
		1 => FinalBreak::Switch {
			day,
			key: hash(5),
			before: hash(4),
			checkpoint: hash(6),
			timeline: "[[\"a\"],[]]".into(),
		},
		2 => FinalBreak::HandOver {
			day,
			line: 3,
			record: rotation(),
			files: "statement:key".into(),
			why: "the key rotation statement is missing".into(),
		},
		3 => FinalBreak::Purge {
			day,
			line: 2,
			record: purge(),
			files: "json:sig:key".into(),
			timeline: "[[\"a\"],[]]".into(),
			why: "the purge statement is missing".into(),
		},
		4 => FinalBreak::AnchorMismatch {
			day,
			anchor: anchor(),
			record: purge(),
		},
		5 => FinalBreak::AnchorOrphan {
			day,
			anchor: anchor(),
		},
		6 => FinalBreak::HeadMissing {
			day,
			end: "7 aa 9".into(),
		},
		7 => FinalBreak::Rollback {
			day,
			head: "{\"time\":1}".into(),
			end: "7 aa 9".into(),
		},
		_ => unreachable!("a kind without a sample"),
	}
}

/// Every leaf of `value`, as the path to it.
fn leaves(value: &Value, path: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
	match value {
		Value::Object(map) => {
			for (key, inner) in map {
				path.push(key.clone());
				leaves(inner, path, out);
				path.pop();
			}
		}
		_ => out.push(path.clone()),
	}
}

fn changed(value: &mut Value, path: &[String]) {
	match path.split_first() {
		None => {
			let next = match &*value {
				Value::String(text) => Value::String(format!("{text}x")),
				Value::Number(number) => Value::from(number.as_u64().unwrap_or(0) + 1),
				Value::Bool(flag) => Value::Bool(!*flag),
				other => Value::String(format!("{other}x")),
			};
			*value = next;
		}
		Some((first, rest)) => {
			if let Some(inner) = value.get_mut(first) {
				changed(inner, rest);
			}
		}
	}
}

#[test]
fn every_kind_has_a_sample_at_its_own_index() {
	for index in 0..KINDS {
		assert_eq!(index_of(&sample_of(index)), index);
	}
}

#[test]
fn changing_any_one_input_of_any_kind_is_another_break() {
	for index in 0..KINDS {
		let sample = sample_of(index);
		let original = sample.to_break().to_string();
		let value = serde_json::to_value(&sample).expect("value");
		let mut paths = Vec::new();
		leaves(&value, &mut Vec::new(), &mut paths);
		assert!(
			paths.len() >= 3,
			"kind {index} has almost no inputs: {paths:?}"
		);
		for path in paths {
			// The tag names the kind; the rest are its inputs.
			if path == ["kind".to_string()] {
				continue;
			}
			let mut other = value.clone();
			changed(&mut other, &path);
			let rebuilt: FinalBreak = serde_json::from_value(other).expect("rebuilt");
			assert_ne!(
				rebuilt.to_break().to_string(),
				original,
				"kind {index}: changing {path:?} kept the same identity"
			);
		}
	}
}

#[test]
fn the_words_stay_when_only_the_state_changes() {
	let a = sample_of(0).to_break().to_string();
	let FinalBreak::Signer {
		day,
		key,
		why,
		timeline,
		..
	} = sample_of(0)
	else {
		unreachable!()
	};
	let b = FinalBreak::Signer {
		day,
		key,
		checkpoint: hash(9),
		why,
		timeline,
	}
	.to_break()
	.to_string();
	let words = |text: &str| text.split(" [state").next().unwrap_or_default().to_string();
	assert_eq!(words(&a), words(&b));
	assert_ne!(a, b);
}
