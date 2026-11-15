#[derive(Clone, Copy)]
pub(in crate::imap::session) enum ResponseCode {
	AuthenticationFailed,
	NonExistent,
	AlreadyExists,
	Cannot,
	NoPerm,
	ClientBug,
	ServerBug,
	Unavailable,
	PrivacyRequired,
}

impl ResponseCode {
	pub(in crate::imap::session) fn value(self) -> &'static str {
		match self {
			Self::AuthenticationFailed => "AUTHENTICATIONFAILED",
			Self::NonExistent => "NONEXISTENT",
			Self::AlreadyExists => "ALREADYEXISTS",
			Self::Cannot => "CANNOT",
			Self::NoPerm => "NOPERM",
			Self::ClientBug => "CLIENTBUG",
			Self::ServerBug => "SERVERBUG",
			Self::Unavailable => "UNAVAILABLE",
			Self::PrivacyRequired => "PRIVACYREQUIRED",
		}
	}
}

pub(in crate::imap::session) fn tagged_no(
	tag: &str,
	code: ResponseCode,
	text: &str,
) -> super::Output {
	super::Output::text(format!("{tag} NO [{}] {text}\r\n", code.value()))
}

pub(in crate::imap::session) fn tagged_bad(
	tag: &str,
	code: ResponseCode,
	text: &str,
) -> super::Output {
	super::Output::text(format!("{tag} BAD [{}] {text}\r\n", code.value()))
}

pub(in crate::imap::session) fn untagged_bad(code: ResponseCode, text: &str) -> super::Output {
	super::Output::text(format!("* BAD [{}] {text}\r\n", code.value()))
}

pub(in crate::imap::session) fn bad_state(tag: &str, text: &str) -> super::Output {
	super::Output::text(format!("{tag} BAD {text}\r\n"))
}
