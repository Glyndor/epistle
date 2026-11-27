//! Taking back a send: `DELETE /api/v1/send/{id}` and the JMAP
//! `EmailSubmission` update, against a server whose send delay holds mail.

mod jmap;
mod removal;
mod rest;
mod support;
