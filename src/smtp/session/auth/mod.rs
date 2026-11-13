//! SMTP AUTH: command dispatch and the PLAIN, LOGIN, OAUTH and SCRAM mechanisms.

pub(super) mod auth_dispatch;
pub(super) mod author;
pub(super) mod login;
pub(super) mod oauth;
pub(super) mod scram;
