-- What an account's own corpus has learned from the user's decisions (moving
-- mail to or from Junk, setting $Junk or $NotJunk), kept so that deciding the
-- same thing twice counts once and a changed mind undoes the earlier lesson.

CREATE TABLE bayes_learned (
	-- The corpus scope: the account name. The shared scope ('') never learns
	-- from a user, so it never appears here.
	scope       TEXT NOT NULL,
	-- Keyed HMAC of the window of the message that was learned, hex encoded.
	-- The same key as the token hashes: the table says nothing about a
	-- message to someone holding only the database.
	digest      TEXT NOT NULL,
	-- The verdict the corpus currently holds for this message: true is spam.
	spam        BOOLEAN NOT NULL,
	-- How many tokens, in the order the tokenizer yields them, were counted
	-- for this message. Taking the lesson back subtracts exactly those, so a
	-- change of the per-lesson token cap between releases cannot subtract
	-- tokens that were never added.
	tokens      INTEGER NOT NULL,
	learned_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (scope, digest)
);

-- One row per account that has learned from a user, or that was switched off.
-- No row means learning is on and nothing has been learned.
CREATE TABLE bayes_learning (
	scope         TEXT PRIMARY KEY,
	-- When false the account's decisions teach nothing.
	enabled       BOOLEAN NOT NULL DEFAULT true,
	-- Messages learned as spam and as ham, counting a message again when the
	-- user changes the verdict.
	spam_learned  BIGINT NOT NULL DEFAULT 0,
	ham_learned   BIGINT NOT NULL DEFAULT 0,
	-- Earlier verdicts taken back because the user decided the other way.
	unlearned     BIGINT NOT NULL DEFAULT 0,
	-- Decisions that repeated what the corpus already held.
	repeated      BIGINT NOT NULL DEFAULT 0,
	-- Decisions refused because the account's table of learned messages is full.
	refused       BIGINT NOT NULL DEFAULT 0,
	-- Rows this account holds in bayes_learned.
	entries       BIGINT NOT NULL DEFAULT 0,
	updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
