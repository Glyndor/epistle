//! The one way to name a destination of the outbound queue.
//!
//! A recipient domain and an exchanger host are destinations of two kinds,
//! kept apart even when their names are equal (a domain `mx.example.net`
//! and the exchanger `mx.example.net` of another domain hold separately).
//! Within a kind, a hold, a fair share or a listing must never see the same
//! one under two spellings (`Example.COM.` and `example.com`, a Unicode
//! name and its A-label). [`Destination`] can only be built through one
//! private function that every constructor calls, so every key in the
//! queue is normalised the same way: IDNA to ASCII, lower case, without the
//! trailing dot.

use std::fmt;

/// Which kind of destination a name is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
	/// The domain of recipient addresses.
	Domain,
	/// A mail exchanger host that answered for a domain.
	Exchanger,
}

impl Kind {
	/// `domain` or `exchanger`.
	pub fn label(self) -> &'static str {
		match self {
			Kind::Domain => "domain",
			Kind::Exchanger => "exchanger",
		}
	}
}

/// A recipient domain or an exchanger host, normalised.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Destination {
	kind: Kind,
	name: String,
}

impl Destination {
	/// The destination of `kind` named `name`: IDNA to ASCII (when `name`
	/// is not a valid name, such as an address literal, it is kept as
	/// written), in lower case, without surrounding blanks or the trailing
	/// dot.
	fn new(kind: Kind, name: &str) -> Self {
		let trimmed = name.trim().trim_end_matches('.');
		let ascii = idna::domain_to_ascii(trimmed).unwrap_or_else(|_| trimmed.to_string());
		Destination {
			kind,
			name: ascii.to_ascii_lowercase(),
		}
	}

	/// The recipient domain `name`.
	pub fn domain(name: &str) -> Self {
		Self::new(Kind::Domain, name)
	}

	/// The exchanger host `host`.
	pub fn exchanger(host: &str) -> Self {
		Self::new(Kind::Exchanger, host)
	}

	/// The destination of a recipient address: its domain.
	pub fn of_recipient(address: &str) -> Self {
		Self::domain(
			address
				.rsplit_once('@')
				.map_or(address, |(_, domain)| domain),
		)
	}

	/// Which kind of destination it is.
	pub fn kind(&self) -> Kind {
		self.kind
	}

	/// The normalised name.
	pub fn as_str(&self) -> &str {
		&self.name
	}
}

impl fmt::Display for Destination {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		out.write_str(&self.name)
	}
}

#[cfg(test)]
mod tests;
