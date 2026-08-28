//! Sieve abstract syntax tree (RFC 5228 §8.2).

/// An argument to a command or test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Argument {
	/// A single string (`"x"` or a `text:` block).
	Str(String),
	/// A bracketed string list (`["a", "b"]`).
	StrList(Vec<String>),
	/// A number, quantifier already applied.
	Number(u64),
	/// A tagged argument (`:contains`).
	Tag(String),
}

/// A test, used as the condition of `if`/`elsif`. `allof`/`anyof` carry a list
/// of child tests; `not` carries exactly one; the rest carry only arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Test {
	/// Test identifier (e.g. `header`, `address`, `allof`, `anyof`, `true`).
	pub name: String,
	/// Positional arguments to the test (string, list, number, tag).
	pub args: Vec<Argument>,
	/// Sub-tests for `allof`/`anyof`/`not`. Empty for tests that take no
	/// child tests.
	pub children: Vec<Test>,
}

/// One branch of a conditional: a test and the commands run when it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branch {
	/// The branch's condition (the test of `if` or `elsif`).
	pub test: Test,
	/// Commands executed when `test` evaluates to true.
	pub body: Vec<Command>,
}

/// A conditional: an `if` branch, zero or more `elsif` branches, and an
/// optional `else` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conditional {
	/// The `if` branch followed by zero or more `elsif` branches. Each is
	/// evaluated in order; the first whose test holds runs.
	pub branches: Vec<Branch>,
	/// Optional `else` body, run when no branch matched.
	pub otherwise: Option<Vec<Command>>,
}

/// A Sieve command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
	/// An action command (`keep`, `discard`, `fileinto "x"`, `require [..]`, …).
	Action {
		/// Action identifier (e.g. `fileinto`, `keep`, `redirect`, `reject`).
		name: String,
		/// Positional arguments to the action.
		args: Vec<Argument>,
	},
	/// A conditional control structure.
	If(Conditional),
}
