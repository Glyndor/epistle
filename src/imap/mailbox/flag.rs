//! IMAP [`Flag`] type, its serde shape, and the helpers that operate on
//! flag sets.
//!
//! The flag type sits next to [`super::Snapshot`] but is split into
//! this module so the per-file line cap holds for the surrounding
//! mailbox file. Callers reach the type through
//! [`crate::imap::mailbox::Flag`], re-exported by [`super`].

/// Supported permanent flags and user-defined keywords (RFC 9051
/// section 2.3.2).
///
/// `Flag` is closed over the five system flags plus the user keyword
/// set. System flags stay `Copy`-able atoms; keywords hold a `String`,
/// so the variant as a whole is no longer `Copy`. Equality ignores
/// case for keywords (RFC 9051 says atoms are matched
/// case-insensitively), but the stored and rendered form preserves
/// the case the client supplied.
///
/// The serde shape is hand-written so sidecars written before user
/// keywords existed still load (a bare string is the system flag, an
/// object with `"name"` is a keyword). The writer always emits the
/// new tagged form so a user keyword whose atom happens to equal a
/// system token cannot be confused with the matching system flag on
/// a round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flag {
	/// `\Seen`: the message has been read.
	Seen,
	/// `\Answered`: a reply has been sent.
	Answered,
	/// `\Flagged`: marked for attention (the "star" in most clients).
	Flagged,
	/// `\Deleted`: marked for removal; expunged at CLOSE or explicit EXPUNGE.
	Deleted,
	/// `\Draft`: not yet sent.
	Draft,
	/// A user-defined keyword atom (`$Junk`, `$Forwarded`, or anything
	/// the operator wants to track). Validated on construct and on
	/// serde-deserialize; see [`crate::imap::keyword::validate`].
	Keyword(crate::imap::keyword::Keyword),
}

impl serde::Serialize for Flag {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		// System flags go out as their lowercase wire token (the format
		// the legacy code wrote, no leading backslash). User keywords
		// go out as `{"name": "..."}` so a keyword whose atom happens
		// to equal a system flag's token cannot be confused with it on
		// the round-trip.
		match self {
			Flag::Seen => serializer.serialize_str("seen"),
			Flag::Answered => serializer.serialize_str("answered"),
			Flag::Flagged => serializer.serialize_str("flagged"),
			Flag::Deleted => serializer.serialize_str("deleted"),
			Flag::Draft => serializer.serialize_str("draft"),
			Flag::Keyword(_) => {
				use serde::ser::SerializeStruct;
				let mut s = serializer.serialize_struct("Flag", 1)?;
				s.serialize_field("name", self.as_str())?;
				s.end()
			}
		}
	}
}

impl<'de> serde::Deserialize<'de> for Flag {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		// Accept two shapes:
		//   - a bare string: a system-flag wire token ("seen", "deleted", ...).
		//     This is the legacy shape; new writers always emit the tagged form.
		//   - an object with `"name"`: a user keyword whose wire token is the
		//     value of `name` (no system flag carries a `name` field).
		struct FlagVisitor;
		impl<'de> serde::de::Visitor<'de> for FlagVisitor {
			type Value = Flag;

			fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				f.write_str("a flag: a bare string (system) or {\"name\":\"...\"} (keyword)")
			}

			fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
			where
				E: serde::de::Error,
			{
				match value {
					"seen" => Ok(Flag::Seen),
					"answered" => Ok(Flag::Answered),
					"flagged" => Ok(Flag::Flagged),
					"deleted" => Ok(Flag::Deleted),
					"draft" => Ok(Flag::Draft),
					other => {
						// Backwards-compat: an older release may have written
						// the full IMAP wire token ("\\Seen") into the
						// sidecar. Strip the leading backslash so that loads
						// from those sidecars still find the right variant.
						let trimmed = other.strip_prefix('\\').unwrap_or(other);
						match trimmed {
							"seen" => Ok(Flag::Seen),
							"answered" => Ok(Flag::Answered),
							"flagged" => Ok(Flag::Flagged),
							"deleted" => Ok(Flag::Deleted),
							"draft" => Ok(Flag::Draft),
							_ => Err(E::invalid_value(
								serde::de::Unexpected::Str(other),
								&"a known system-flag token",
							)),
						}
					}
				}
			}

			fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
			where
				A: serde::de::MapAccess<'de>,
			{
				let mut name: Option<String> = None;
				while let Some(key) = map.next_key::<String>()? {
					match key.as_str() {
						"name" => name = Some(map.next_value()?),
						other => {
							let _: serde::de::IgnoredAny = map.next_value()?;
							return Err(serde::de::Error::unknown_field(other, &["name"]));
						}
					}
				}
				let raw = name.ok_or_else(|| serde::de::Error::missing_field("name"))?;
				crate::imap::keyword::Keyword::new(&raw)
					.map(Flag::Keyword)
					.map_err(|reason| {
						serde::de::Error::custom(format!("invalid keyword {raw:?}: {reason}"))
					})
			}
		}
		deserializer.deserialize_any(FlagVisitor)
	}
}

impl Flag {
	/// Parse the IMAP flag token. System tokens (`\Seen`, `\Answered`,
	/// `\Flagged`, `\Deleted`, `\Draft`) map to their variants; any
	/// atom without a leading `\` is parsed as a [`Flag::Keyword`].
	///
	/// Returns `None` only when the token is rejected by the keyword
	/// validator: that covers leading `\`, spaces, atom-specials,
	/// control bytes, non-ASCII bytes, and length >64.
	pub fn parse(token: &str) -> Option<Flag> {
		match token.to_ascii_lowercase().as_str() {
			"\\seen" => Some(Flag::Seen),
			"\\answered" => Some(Flag::Answered),
			"\\flagged" => Some(Flag::Flagged),
			"\\deleted" => Some(Flag::Deleted),
			"\\draft" => Some(Flag::Draft),
			_ => {
				// Anything without a leading `\` is a user keyword.
				if token.starts_with('\\') {
					None
				} else {
					crate::imap::keyword::Keyword::new(token)
						.ok()
						.map(Flag::Keyword)
				}
			}
		}
	}

	/// The wire representation: the canonical token for a system flag,
	/// or the raw keyword for a user keyword (case preserved).
	pub fn as_str(&self) -> &str {
		match self {
			Flag::Seen => "\\Seen",
			Flag::Answered => "\\Answered",
			Flag::Flagged => "\\Flagged",
			Flag::Deleted => "\\Deleted",
			Flag::Draft => "\\Draft",
			Flag::Keyword(keyword) => keyword.as_str(),
		}
	}

	/// Whether the flag is a user-defined keyword (not one of the five
	/// system flags). Used by code that needs to iterate the keyword
	/// set (the SELECT response, the trainer, JMAP round-trip).
	pub fn is_keyword(&self) -> bool {
		matches!(self, Flag::Keyword(_))
	}

	/// The keyword name when the flag is a [`Flag::Keyword`], else
	/// `None`. The returned `Keyword` is built fresh on every call
	/// (validation runs each time) so callers that need a longer-lived
	/// reference should clone via [`Flag::keyword_name`].
	pub fn keyword(&self) -> Option<&crate::imap::keyword::Keyword> {
		match self {
			Flag::Keyword(keyword) => Some(keyword),
			_ => None,
		}
	}

	/// The raw keyword token (the `$`-prefixed atom, case preserved)
	/// for a [`Flag::Keyword`], else `None`. Cheaper than
	/// [`Flag::keyword`] when the caller only needs the string.
	pub fn keyword_name(&self) -> Option<&str> {
		match self {
			Flag::Keyword(keyword) => Some(keyword.as_str()),
			_ => None,
		}
	}

	/// True iff the flag is the reserved `$Junk` keyword
	/// (case-insensitive).
	pub fn is_junk(&self) -> bool {
		matches!(self, Flag::Keyword(k) if k.is_junk())
	}

	/// True iff the flag is the reserved `$NotJunk` keyword
	/// (case-insensitive).
	pub fn is_not_junk(&self) -> bool {
		matches!(self, Flag::Keyword(k) if k.is_not_junk())
	}
}

/// Render a flag list for FETCH/STORE responses.
///
/// Builds the parenthesized list in a single pre-sized allocation,
/// without the intermediate `Vec<&str>` that `join` would require:
/// this runs once per message in every FETCH FLAGS / STORE response.
pub fn render_flags(flags: &[Flag]) -> String {
	// "(" + ")" + flag tokens + single-space separators between them.
	let capacity = 2
		+ flags.iter().map(|flag| flag.as_str().len()).sum::<usize>()
		+ flags.len().saturating_sub(1);
	let mut out = String::with_capacity(capacity);
	out.push('(');
	for (index, flag) in flags.iter().enumerate() {
		if index > 0 {
			out.push(' ');
		}
		out.push_str(flag.as_str());
	}
	out.push(')');
	out
}

/// A canonical lookup key for a flag. System flags map to their
/// lowercase canonical name; keywords map to the lowercased token.
/// Used to dedup and to test membership without re-parsing the
/// keyword each time.
pub fn flag_key(flag: &Flag) -> String {
	match flag {
		Flag::Seen => "seen".to_string(),
		Flag::Answered => "answered".to_string(),
		Flag::Flagged => "flagged".to_string(),
		Flag::Deleted => "deleted".to_string(),
		Flag::Draft => "draft".to_string(),
		Flag::Keyword(keyword) => keyword.as_str().to_ascii_lowercase(),
	}
}

/// Whether a flag set already contains `flag`, treating keywords as
/// case-insensitive (the IMAP atom matching rule). Used by STORE to
/// decide whether adding `flag` would add a duplicate.
pub fn flag_set_contains(set: &[Flag], flag: &Flag) -> bool {
	let needle = flag_key(flag);
	set.iter().any(|existing| flag_key(existing) == needle)
}

/// The keywords in a flag set, deduplicated case-insensitively.
/// System flags are ignored. Returns owned `Keyword`s so the caller
/// keeps them alive without borrowing against the flag list.
pub fn keywords_in(flags_list: &[Flag]) -> Vec<crate::imap::keyword::Keyword> {
	let mut seen: Vec<String> = Vec::new();
	let mut out: Vec<crate::imap::keyword::Keyword> = Vec::new();
	for flag in flags_list {
		if let Flag::Keyword(keyword) = flag
			&& !seen
				.iter()
				.any(|s| s.eq_ignore_ascii_case(keyword.as_str()))
		{
			seen.push(keyword.as_str().to_string());
			// The cloned keyword keeps the borrowed lifetime of the
			// original; build a fresh `Keyword` to detach ownership.
			if let Ok(fresh) = crate::imap::keyword::Keyword::new(keyword.as_str()) {
				out.push(fresh);
			}
		}
	}
	out
}

/// Count the keywords in `flags`. `None` when the count exceeds the
/// per-message cap [`crate::imap::keyword::MAX_KEYWORDS_PER_MESSAGE`].
pub fn count_keywords(flags: &[Flag]) -> Option<usize> {
	let count = flags.iter().filter(|flag| flag.is_keyword()).count();
	if count > crate::imap::keyword::MAX_KEYWORDS_PER_MESSAGE {
		None
	} else {
		Some(count)
	}
}

/// Keep the first occurrence of every flag, in order. Keywords that
/// differ only in case are the same flag (see [`flag_key`]).
pub fn dedup_flags(flags_list: &mut Vec<Flag>) {
	let mut seen: Vec<String> = Vec::with_capacity(flags_list.len());
	flags_list.retain(|flag| {
		let key = flag_key(flag);
		if seen.contains(&key) {
			false
		} else {
			seen.push(key);
			true
		}
	});
}
