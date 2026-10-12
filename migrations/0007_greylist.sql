-- Greylist triplets: per (client IP, envelope sender, recipient) the
-- UNIX time the triplet was first seen, when (if ever) it passed
-- the delay, and when it was last touched. State lives here so a
-- restart does not re-defer every legitimate sender while the
-- anti-spam feature is on.
--
-- Key is text: greylist.rs builds the lowercase, pipe-separated
-- representation of (client_ip, sender, recipient) so case
-- variations collapse to one row. The expire sweep uses the
-- `first_seen` index because the policy is "drop anything older
-- than the configured lifetime".

CREATE TABLE greylist_triplet (
	-- The composite key produced by `greylist::Triplet::key()`.
	key            TEXT PRIMARY KEY,
	-- UNIX seconds of the first attempt. The expire sweep reads
	-- this for its range predicate.
	first_seen     BIGINT NOT NULL,
	-- UNIX seconds of the first retry that waited out the delay.
	-- `NULL` while the triplet is still in deferral; populated
	-- once the sender actually retried past the threshold.
	passed_at      BIGINT,
	-- UNIX seconds of the most recent attempt: lets the sweep
	-- keep actively-used triplets even when `first_seen` is old.
	last_seen      BIGINT NOT NULL,
	created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Sweep index: the expire pass deletes triplets whose
-- first_seen is older than the lifetime window.
CREATE INDEX greylist_triplet_first_seen ON greylist_triplet (first_seen);
