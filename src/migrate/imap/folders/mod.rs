//! Deciding which remote folders are copied and where each one lands.
//!
//! A remote name is untrusted input that ends up naming a directory, so it
//! is never rewritten into something storable: it is mapped by a fixed rule
//! (the remote hierarchy delimiter becomes [`LOCAL_DELIMITER`]) and then
//! checked by the same rule every other mailbox name passes
//! ([`crate::imap::mailbox::valid_name`]). A name that fails is reported
//! and skipped with the reason.

use super::parse::ListEntry;

/// The hierarchy separator of local mailbox names.
pub(crate) const LOCAL_DELIMITER: char = '/';

/// Why a remote folder is not copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SkipReason {
	/// It only holds other folders (`\Noselect` or `\NonExistent`).
	NotSelectable,
	/// A virtual view of other folders (`\All`, `\Flagged`): copying it
	/// would duplicate every message it shows.
	Virtual,
	/// Left out by `--folders`.
	Filtered,
	/// It contains the local separator inside one of its components.
	SeparatorInName,
	/// The mapped name is not a valid local mailbox name.
	InvalidName,
}

impl std::fmt::Display for SkipReason {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			SkipReason::NotSelectable => "holds only other folders",
			SkipReason::Virtual => {
				"virtual folder (a view of other folders); name it in --folders to copy it"
			}
			SkipReason::Filtered => "excluded by --folders",
			SkipReason::SeparatorInName => {
				"a folder name contains '/', the local hierarchy separator"
			}
			SkipReason::InvalidName => "the name cannot be stored as a local mailbox",
		})
	}
}

/// One remote folder and what happens to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
	/// The remote name as the server sent it, used in commands and state.
	pub(crate) remote: Vec<u8>,
	/// The remote name for people: modified UTF-7 decoded, lossy.
	pub(crate) display: String,
	/// The local mailbox, or why the folder is skipped.
	pub(crate) local: Result<String, SkipReason>,
}

/// Include and exclude patterns from `--folders`. A pattern starting with
/// `!` excludes; `*` matches any run of characters. With no include
/// pattern every folder is included.
#[derive(Debug, Clone, Default)]
pub(crate) struct Filter {
	include: Vec<String>,
	exclude: Vec<String>,
}

impl Filter {
	/// Build a filter from `--folders` values.
	pub(crate) fn new(patterns: &[String]) -> Self {
		let mut filter = Filter::default();
		for pattern in patterns {
			match pattern.strip_prefix('!') {
				Some(excluded) => filter.exclude.push(excluded.to_string()),
				None => filter.include.push(pattern.clone()),
			}
		}
		filter
	}

	/// Whether `name` is copied.
	pub(crate) fn admits(&self, name: &str) -> bool {
		(self.include.is_empty() || self.include.iter().any(|p| glob(p, name)))
			&& !self.exclude.iter().any(|p| glob(p, name))
	}

	/// Whether an include pattern names `name` exactly (no wildcard), the
	/// opt-in for a virtual folder.
	fn names(&self, name: &str) -> bool {
		self.include.iter().any(|pattern| pattern == name)
	}
}

/// Match `name` against `pattern`, where `*` stands for any run of
/// characters. The classic single-backtrack algorithm: linear in the
/// common case and at most `pattern × name` steps, with no recursion.
pub(crate) fn glob(pattern: &str, name: &str) -> bool {
	let (pattern, name): (Vec<char>, Vec<char>) =
		(pattern.chars().collect(), name.chars().collect());
	let (mut p, mut n) = (0, 0);
	let mut star: Option<(usize, usize)> = None;
	while n < name.len() {
		if p < pattern.len() && pattern[p] == '*' {
			star = Some((p, n));
			p += 1;
		} else if p < pattern.len() && pattern[p] == name[n] {
			p += 1;
			n += 1;
		} else if let Some((star_p, star_n)) = star {
			p = star_p + 1;
			n = star_n + 1;
			star = Some((star_p, star_n + 1));
		} else {
			return false;
		}
	}
	pattern[p..].iter().all(|&c| c == '*')
}

/// The local mailbox a special-use attribute maps to.
fn special(attributes: &[String]) -> Option<Result<&'static str, SkipReason>> {
	attributes.iter().find_map(|attribute| {
		Some(match attribute.as_str() {
			"\\inbox" => Ok("INBOX"),
			"\\sent" => Ok("Sent"),
			"\\drafts" => Ok("Drafts"),
			"\\trash" => Ok("Trash"),
			"\\junk" | "\\spam" => Ok("Junk"),
			"\\archive" => Ok("Archive"),
			"\\all" | "\\allmail" | "\\flagged" | "\\starred" | "\\important" => {
				Err(SkipReason::Virtual)
			}
			_ => return None,
		})
	})
}

/// Decide what happens to every listed folder. `namespace` is the personal
/// namespace prefix (`INBOX.` on servers that nest everything under the
/// inbox), stripped before mapping.
pub(crate) fn plan(entries: &[ListEntry], namespace: Option<&[u8]>, filter: &Filter) -> Vec<Plan> {
	let mut plans: Vec<Plan> = entries
		.iter()
		.map(|entry| {
			let display = display_name(&entry.name);
			let local = map(entry, namespace, filter, &display);
			Plan {
				remote: entry.name.clone(),
				display,
				local,
			}
		})
		.collect();
	// INBOX first, then by name, so a run reads the same every time.
	plans.sort_by(|a, b| {
		let inbox = |plan: &Plan| !plan.remote.eq_ignore_ascii_case(b"INBOX");
		(inbox(a), &a.display).cmp(&(inbox(b), &b.display))
	});
	plans.dedup_by(|a, b| a.remote == b.remote);
	plans
}

fn map(
	entry: &ListEntry,
	namespace: Option<&[u8]>,
	filter: &Filter,
	display: &str,
) -> Result<String, SkipReason> {
	if entry
		.attributes
		.iter()
		.any(|a| a == "\\noselect" || a == "\\nonexistent")
	{
		return Err(SkipReason::NotSelectable);
	}
	let special = special(&entry.attributes);
	if special == Some(Err(SkipReason::Virtual)) && !filter.names(display) {
		return Err(SkipReason::Virtual);
	}
	if !filter.admits(display) {
		return Err(SkipReason::Filtered);
	}
	if entry.name.eq_ignore_ascii_case(b"INBOX") {
		return Ok("INBOX".to_string());
	}
	if let Some(Ok(local)) = special {
		return Ok(local.to_string());
	}
	local_name(&entry.name, entry.delimiter, namespace)
}

/// Map a remote name to the local spelling: strip the personal namespace
/// prefix, swap the remote delimiter for [`LOCAL_DELIMITER`], keep the
/// modified UTF-7 spelling the local store uses, and check the result.
pub(crate) fn local_name(
	remote: &[u8],
	delimiter: Option<u8>,
	namespace: Option<&[u8]>,
) -> Result<String, SkipReason> {
	let mut name = remote;
	if let Some(prefix) = namespace.filter(|prefix| !prefix.is_empty())
		&& name.len() > prefix.len()
		&& name[..prefix.len()].eq_ignore_ascii_case(prefix)
	{
		name = &name[prefix.len()..];
	}
	let text = std::str::from_utf8(name).map_err(|_| SkipReason::InvalidName)?;
	// A server that sent UTF-8 names gets them in the stored spelling.
	let text = if text.is_ascii() {
		text.to_string()
	} else {
		crate::util::mutf7::encode(text)
	};
	let mapped = match delimiter.map(char::from) {
		Some(remote) if remote != LOCAL_DELIMITER => {
			if text.contains(LOCAL_DELIMITER) {
				return Err(SkipReason::SeparatorInName);
			}
			text.replace(remote, &LOCAL_DELIMITER.to_string())
		}
		Some(_) => text,
		// A flat namespace has no hierarchy: a '/' there is part of a name.
		None if text.contains(LOCAL_DELIMITER) => return Err(SkipReason::SeparatorInName),
		None => text,
	};
	if mapped
		.split(LOCAL_DELIMITER)
		.any(|component| component.is_empty())
		|| !crate::imap::mailbox::valid_name(&mapped)
	{
		return Err(SkipReason::InvalidName);
	}
	Ok(mapped)
}

/// A remote name for people: modified UTF-7 decoded when it decodes.
fn display_name(remote: &[u8]) -> String {
	let lossy = String::from_utf8_lossy(remote);
	crate::util::mutf7::decode(&lossy).unwrap_or_else(|| lossy.into_owned())
}

#[cfg(test)]
mod tests;
