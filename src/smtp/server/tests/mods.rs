//! The test-module declarations for the SMTP server. The list lives
//! in its own file so the listener implementation does not have to
//! grow past the 500-code-line limit just to declare every sibling
//! test module. The `pub use super::*;` re-exports the parent
//! module's items (which are now `pub use` so the test files'
//! `use super::*;` still picks them up).

pub use super::*;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_auth;

#[cfg(test)]
mod tests_bcc;

#[cfg(test)]
mod tests_trace;

#[cfg(test)]
mod gone;

#[cfg(test)]
mod class;

#[cfg(test)]
mod tests_save_sent;

#[cfg(test)]
mod tests_sent_refused;

#[cfg(test)]
mod tests_correspondents;

#[cfg(test)]
mod tests_subjectpass;

#[cfg(test)]
mod tests_dual_stack;

#[cfg(test)]
mod tests_starttls;

#[cfg(test)]
mod tests_author;

#[cfg(test)]
mod tests_sender_verified;

#[cfg(test)]
mod tests_recipients;

#[cfg(test)]
mod tests_quota;

#[cfg(test)]
mod accept_log;

#[cfg(test)]
mod rate;

#[cfg(test)]
mod bdat;

#[cfg(test)]
mod headers;

#[cfg(test)]
mod scanning;

#[cfg(test)]
mod limits;
