//! The test-module declarations for the SMTP server. The list lives
//! in its own file so the listener implementation does not have to
//! grow past the 500-code-line limit just to declare every sibling
//! test module. The `pub use super::*;` re-exports the parent
//! module's items (which are now `pub use` so the test files'
//! `use super::*;` still picks them up).

pub use super::*;

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "server_tests_auth.rs"]
mod tests_auth;

#[cfg(test)]
#[path = "server_tests_bcc.rs"]
mod tests_bcc;

#[cfg(test)]
#[path = "server_tests_virus.rs"]
mod tests_virus;

#[cfg(test)]
#[path = "server_tests_trace.rs"]
mod tests_trace;

#[cfg(test)]
#[path = "server_tests_urlbl.rs"]
mod tests_urlbl;

#[cfg(test)]
#[path = "server_tests_save_sent.rs"]
mod tests_save_sent;

#[cfg(test)]
#[path = "server_tests_correspondents.rs"]
mod tests_correspondents;

#[cfg(test)]
#[path = "server_tests_subjectpass.rs"]
mod tests_subjectpass;

#[cfg(test)]
#[path = "server_tests_dual_stack.rs"]
mod tests_dual_stack;

#[cfg(test)]
#[path = "server_tests_starttls.rs"]
mod tests_starttls;

#[cfg(test)]
#[path = "server_tests_author.rs"]
mod tests_author;

#[cfg(test)]
#[path = "server_tests_per_ip.rs"]
mod tests_per_ip;

#[cfg(test)]
#[path = "server_tests_budget.rs"]
mod tests_budget;
#[cfg(test)]
#[path = "server_tests_sender_verified.rs"]
mod tests_sender_verified;

#[cfg(test)]
#[path = "server_tests_data_rate.rs"]
mod tests_data_rate;

#[cfg(test)]
#[path = "server_tests_data_rate_bdat.rs"]
mod tests_data_rate_bdat;

#[cfg(test)]
#[path = "server_tests_data_rate_config.rs"]
mod tests_data_rate_config;

#[cfg(test)]
#[path = "server_tests_data_rate_writes.rs"]
mod tests_data_rate_writes;

#[cfg(test)]
#[path = "server_tests_data_rate_legit.rs"]
mod tests_data_rate_legit;

#[cfg(test)]
#[path = "server_tests_tls_drip.rs"]
mod tests_tls_drip;
