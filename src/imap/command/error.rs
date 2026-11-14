//! Why a client line failed to parse.

/// Why a line failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
	/// No tag or malformed structure: answered with `* BAD`.
	Malformed,
	/// Valid tag but unknown/unsupported command: tagged `BAD`.
	Unknown(String),
	/// Valid tag, known command, bad arguments: tagged `BAD`.
	BadArguments(String),
	/// Valid tag, APPEND or REPLACE whose literal exceeds the advertised
	/// APPENDLIMIT: tagged `NO [TOOBIG]` (RFC 7889 §3).
	TooBig(String),
}
