//! The send switch over the API and JMAP: an account whose sending is off
//! submits nothing through `POST /api/v1/send` or `EmailSubmission/set`, and
//! sets up no auto-reply or redirect that would send for it, while an account
//! beside it keeps working.

mod jmap_submission;
mod rules;
mod send;
mod support;
