//! The test-module declarations for the SMTP session. The list lives
//! in its own file so the state-machine implementation does not have
//! to grow past the 500-code-line limit just to declare every
//! sibling test module. The `pub use super::*;` re-exports the
//! parent module's items (which are now `pub use` so the test files'
//! `use super::*;` still picks them up).

pub use super::*;

#[cfg(test)]
mod tests_basic;

#[cfg(test)]
mod tests_enhanced;

#[cfg(test)]
mod tests_bdat_framing;
#[cfg(test)]
mod tests_newrecipients;
#[cfg(test)]
mod tests_recipients;
#[cfg(test)]
mod tests_single_label;

#[cfg(test)]
mod scram;

#[cfg(test)]
mod auth;

#[cfg(test)]
mod limits;

#[cfg(test)]
mod junk;
