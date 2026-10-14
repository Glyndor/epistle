//! The one way to name a destination of the outbound queue.
//!
//! A recipient domain and an exchanger host are both destinations, and a
//! hold, a fair share or a listing must never see the same one under two
//! spellings (`Example.COM.` and `example.com`, a Unicode name and its
//! A-label). [`Destination`] can only be built by [`Destination::new`], so
//! every key in the queue is normalised the same way: IDNA to ASCII, lower
//! case, without the trailing dot.

use std::fmt;

/// A recipient domain or an exchanger host, normalised.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Destination(String);

impl Destination {
	/// The destination named `name`: IDNA to ASCII (when `name` is not a
	/// valid name, such as an address literal, it is kept as written), in
	/// lower case, without surrounding blanks or the trailing dot.
	pub fn new(name: &str) -> Self {
		let trimmed = name.trim().trim_end_matches('.');
		let ascii = idna::domain_to_ascii(trimmed).unwrap_or_else(|_| trimmed.to_string());
		Destination(ascii.to_ascii_lowercase())
	}

	/// The destination of a recipient address: its domain.
	pub fn of_recipient(address: &str) -> Self {
		Self::new(
			address
				.rsplit_once('@')
				.map_or(address, |(_, domain)| domain),
		)
	}

	/// The normalised name.
	pub fn as_str(&self) -> &str {
		&self.0
	}
}

impl fmt::Display for Destination {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		out.write_str(&self.0)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn every_spelling_of_a_name_is_one_destination() {
		for spelling in [
			"example.com",
			"Example.COM",
			"example.com.",
			" EXAMPLE.com. ",
		] {
			assert_eq!(
				Destination::new(spelling).as_str(),
				"example.com",
				"{spelling:?}"
			);
		}
		assert_eq!(
			Destination::new("bücher.example").as_str(),
			"xn--bcher-kva.example"
		);
		assert_eq!(
			Destination::new("BÜCHER.example."),
			Destination::new("xn--bcher-kva.example")
		);
		assert_eq!(
			Destination::of_recipient("Bob@Mx.Example.COM."),
			Destination::new("mx.example.com")
		);
		// A name IDNA refuses is still one key, whatever its case.
		assert_eq!(
			Destination::new("XN--ZZZZ.Example.").as_str(),
			"xn--zzzz.example"
		);
	}
}
