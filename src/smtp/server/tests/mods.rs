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
mod tests_virus;

#[cfg(test)]
mod tests_attachments;

#[cfg(test)]
mod tests_clamd_defer;
#[cfg(test)]
mod tests_clamd_toolarge;

#[cfg(test)]
mod tests_trace;

#[cfg(test)]
mod tests_urlbl;

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
mod tests_per_ip;

#[cfg(test)]
mod tests_budget;
#[cfg(test)]
mod tests_sender_verified;

#[cfg(test)]
mod tests_data_rate;

#[cfg(test)]
mod tests_data_rate_bdat;

#[cfg(test)]
mod tests_data_rate_config;

#[cfg(test)]
mod tests_data_rate_writes;

#[cfg(test)]
mod tests_data_rate_legit;

#[cfg(test)]
mod tests_tls_drip;

#[cfg(test)]
mod tests_bdat_growth;

#[cfg(test)]
mod tests_bdat_framing;

#[cfg(test)]
mod tests_session_limits;

#[cfg(test)]
mod tests_header_fields;

#[cfg(test)]
mod tests_recipients;

#[cfg(test)]
mod tests_session_time;

#[cfg(test)]
mod tests_session_time_abuse;

#[cfg(test)]
mod tests_bdat_share;

#[cfg(test)]
mod tests_attachments_flood;

#[cfg(test)]
mod tests_inbound_headers;

#[cfg(test)]
mod tests_inbound_headers_unicode;

#[cfg(test)]
mod tests_inbound_order;

#[cfg(test)]
mod tests_quota;

#[cfg(test)]
mod tests_drain;

#[cfg(test)]
mod accept_log;
