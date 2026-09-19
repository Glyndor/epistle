//! Antispam engine: reputation, scoring and screening.
//!
//! Storage-backed components (reputation, and later the statistical
//! classifier) live here on top of the PostgreSQL pool; stateless screens
//! such as DNSBL live in their own modules.

pub mod arf;
pub mod bans;
pub mod bayes;
pub mod clamd;
pub mod corpus;
pub mod greylist;
pub mod hook;
pub mod llm;
pub mod reputation;
pub mod subjectpass;
pub mod trainer;
pub mod training_queue;
pub mod urls;
