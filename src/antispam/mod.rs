//! Antispam engine: reputation, scoring and screening.
//!
//! Storage-backed components (reputation, and later the statistical
//! classifier) live here on top of the PostgreSQL pool; stateless screens
//! such as DNSBL live in their own modules.

pub mod bayes;
pub mod corpus;
pub mod reputation;
