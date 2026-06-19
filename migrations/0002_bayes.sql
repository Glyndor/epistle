-- Bayesian classifier corpus: per-token ham/spam counts and message totals.

CREATE TABLE bayes_token (
	id          UUID PRIMARY KEY,
	token       TEXT NOT NULL UNIQUE,
	ham_count   BIGINT NOT NULL DEFAULT 0,
	spam_count  BIGINT NOT NULL DEFAULT 0,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Single-row table of trained message totals (the classifier's denominators).
CREATE TABLE bayes_corpus (
	singleton      BOOLEAN PRIMARY KEY DEFAULT true,
	ham_messages   BIGINT NOT NULL DEFAULT 0,
	spam_messages  BIGINT NOT NULL DEFAULT 0,
	updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT bayes_corpus_singleton CHECK (singleton)
);

INSERT INTO bayes_corpus (singleton) VALUES (true);
