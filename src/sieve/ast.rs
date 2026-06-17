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
	pub name: String,
	pub args: Vec<Argument>,
	pub children: Vec<Test>,
}

/// One branch of a conditional: a test and the commands run when it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branch {
	pub test: Test,
	pub body: Vec<Command>,
}

/// A conditional: an `if` branch, zero or more `elsif` branches, and an
/// optional `else` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conditional {
	pub branches: Vec<Branch>,
	pub otherwise: Option<Vec<Command>>,
}

/// A Sieve command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
	/// An action command (`keep`, `discard`, `fileinto "x"`, `require [..]`, …).
	Action { name: String, args: Vec<Argument> },
	/// A conditional control structure.
	If(Conditional),
}
