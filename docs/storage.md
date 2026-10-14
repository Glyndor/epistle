# Storage

How the outbound spool is laid out on disk, what protects it, and how to
check it with `epistle status`.

## Outbound spool

`data_dir/spool/` holds the outbound queue. Every accepted message is two
files under one id (a UUID v7):

- `spool/new/<id>.eml`: the raw message.
- `spool/new/<id>.json`: the envelope (sender, recipients, per-recipient
  state, last error).

Both are written under `spool/tmp/`, fsynced and renamed into `spool/new/`,
body first and envelope last, so a visible envelope always has a complete
body next to it. `spool/lock` is the `flock(2)` file the delivery worker and
the operator commands take before editing or removing an entry.

## File permissions

Spool files are created at `0600` and directories at `0700`, whatever the
umask: the mode is set when the file is created, not changed afterwards.

At start-up the server retightens a spool written by an older version: the
root, `tmp/`, `new/` and the `.eml`, `.json` and `lock` files directly in
them. It logs how many files it changed. Each path is opened without
following links and changed through the open descriptor, and only paths
owned by the owner of the spool root are touched. If any path cannot be
checked or fixed, the server refuses to start rather than run on a spool
other users may read.

## Envelope encryption

With `encrypt_at_rest = true` the envelope is sealed like the body, with
ChaCha20-Poly1305 under the same key and a fresh random nonce on every
write, and with the message id as associated data:

```
MAGIC ‖ nonce(12) ‖ ciphertext ‖ tag(16)
```

- An envelope copied over another message's envelope fails to decrypt.
- A changed or truncated envelope fails to decrypt.
- A sealed envelope read with no key loaded fails with "no key is loaded".

An envelope that fails is never delivered with defaults and never deleted:
it stays in `spool/new/`, the worker logs it on every pass and skips it, and
`epistle status` counts it as unreadable.

### Upgrading from 0.12.0

Envelopes written before encryption are plaintext. They are read as they
are, rewritten sealed on the next read (atomically, through `tmp/`), and
the first edit (an attempt, a hold) writes them sealed too. Bodies written
before encryption stay plaintext until the message leaves the queue.

Turning `encrypt_at_rest` off with the key still configured keeps reading
sealed envelopes; new writes are plaintext.

### Limits

- Encryption protects a stolen disk or backup. Anyone who can write to the
  spool can still put a plaintext envelope in place of a sealed one, since
  plaintext is accepted for the upgrade, and can swap two bodies, since a
  body is not bound to its id.
- 0.12.0 cannot read sealed envelopes. After a downgrade those messages stay
  queued and skipped until the newer version runs again; nothing is
  deleted.

## `epistle status`

The `spool` area reports whether `encrypt_at_rest` is on and how many spool
paths are looser than owner-only:

```
spool   ok    sealed: yes, loose: 0
```

It only reads: it never changes a mode and never creates the spool. A
non-zero `loose` count is a warning. The `queue` area reads the envelopes
with the configured key and counts the ones it cannot read.
