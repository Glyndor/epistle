-- Per-subject authentication failures and active bans, shared across every
-- listener (SMTP submission, IMAP, POP3, ManageSieve, the API and OAuth
-- grants). The product context's default is: ban after 5 failed
-- authentications in 15 minutes, with exponential backoff at 15 minutes,
-- 30 minutes, 1 hour, 2 hours, ... capped at 24 hours. A successful
-- authentication clears both the ban and the failure history for the
-- subject, so the counter starts fresh after a clean sign-in.

CREATE TABLE auth_failure (
	-- The failure id; UUIDv7 to keep inserts distributed.
	id          UUID PRIMARY KEY,
	-- The subject the failure counts against. `'ip:<addr>'` for client IP
	-- bans (every listener sees the same address for the same client) and
	-- `'account:<login>'` for account-name bans (the login name as the
	-- client presented it, lowercased by the caller).
	subject     TEXT NOT NULL,
	-- The protocol the failure happened on (`smtp`, `imap`, `pop3`,
	-- `managesieve`, `api`, `webdav`). Stored for the audit trail; the
	-- ban itself is protocol-agnostic.
	protocol    TEXT NOT NULL,
	-- When the failure was recorded. Indexed with `subject` so the
	-- rolling 15-minute window scan is a single index range.
	seen_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The hot read pattern is "every failure for `subject` in the last
-- 15 minutes", so the composite index is the natural fit.
CREATE INDEX auth_failure_subject_seen_at ON auth_failure (subject, seen_at);

CREATE TABLE auth_ban (
	-- The subject the ban applies to (`'ip:<addr>'` or `'account:<name>'`).
	subject     TEXT PRIMARY KEY,
	-- How many bans have stacked on this subject. The first ban is 1,
	-- the next on the same subject is 2, and so on; the backoff is
	-- `BASE * 2^(strikes-1)` capped at 24 hours.
	strikes     INTEGER NOT NULL DEFAULT 1,
	-- When the ban expires. The directory refuses every authentication
	-- for this subject while `now() < until`, so a check is a single
	-- point lookup with no second index needed.
	until       TIMESTAMPTZ NOT NULL,
	-- The rule that fired the ban (e.g. `'5 failed authentications in 15 minutes'`).
	-- Kept verbatim for the audit log; the wire reply never includes it.
	reason      TEXT NOT NULL,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
