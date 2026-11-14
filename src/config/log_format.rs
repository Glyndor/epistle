//! The format the server writes its log in.

use serde::Deserialize;

/// Log output format.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
	/// Human-readable text (the default).
	#[default]
	Text,
	/// Structured JSON, one object per event.
	Json,
}
