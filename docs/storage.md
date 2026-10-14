# Storage

How the on-disk stores are laid out, what protects the file modes and the
sealed envelopes, and how an operator can answer "is the spool actually
encrypted and is every file owner-only" without reading mail content.

## Outbound spool

`data_dir/spool/` holds the outbound queue. Every accepted message becomes two
files under one id (a UUID v7 minted at submission):

- `spool/new/<id>.eml` ,  the raw RFC 5322 bytes the SMTP/LMTP/JMAP/API hop
  accepted. Written owner-only.
- `spool/new/<id>.json` ,  the envelope: sender (`reverse_path`), recipients,
  per-recipient state and the last error string. Bound to the message id and
  sealed when `encrypt_at_rest = true`. Written owner-only.

Files are staged to `spool/tmp/` and renamed into `spool/new/` so a crash
mid-write never leaves a partial file: a `spool/new/<id>.eml` without its
envelope next to it is invisible. The rename order is body first, envelope
last, so a visible envelope guarantees a complete body.

`spool/lock` is the `flock(2)` file the delivery worker and the operator CLI
take before editing or removing an entry. It is owner-only so an unrelated
user cannot tell from `fs` that the server is mid-edit.

## File permissions (Item 1)

Every spool file and directory is created at mode `0600` (files) or `0700`
(directories), regardless of the umask under which the server was started.
`OpenOptionsExt::mode` and `DirBuilderExt::mode` pin the mode at create, so
nothing is briefly group- or world-readable between `creat(2)` and the
`fsync(2)` that follows.

For a spool written before this code path existed, the server runs an audit
once at start-up (`SplitDelivery::new_with_crypto` calls
`FsSpool::audit_permissions`):

- every directory whose mode is looser than `0700` is silently retightened,
- every file ending in `.eml`, `.json` or named `lock` whose mode is looser
  than `0600` is retightened and counted,
- the count of files retightened is logged once at level `INFO`:
  `tightened N spool file/directory permissions to owner-only`.

If the operator's `data_dir` lives on a filesystem with weird permissions
semantics (NFS without `no_root_squash`, an immutable volume), the audit may
fail and warn; the spool keeps running and the loose files stay loose.
`epistle status`'s `spool` line reports whatever the on-disk state is, so
the operator sees it.

The audit is bounded: a linear walk of `data_dir/spool/{tmp,new,lock}`, no
recursion into attacker-controlled filenames (entries whose name is not one
plain path component are skipped), so a queue that grows into millions of
messages does not produce an O(n^2) scan.

## Envelope at-rest encryption (Item 2)

The envelope is sealed with **ChaCha20-Poly1305** under the same key the body
uses, with the **message id** as associated data:

```
AEAD envelope = MAGIC ‖ nonce(12) ‖ ciphertext ‖ tag(16)
```

A file that does not start with `MAGIC` (`b"EPENC1\0"`) is treated as legacy
plaintext; this is how the migration works:

1. Operator turns `encrypt_at_rest = true`. New writes seal both the body and
   the envelope.
2. The next read of a legacy plaintext envelope returns the envelope to the
   caller, then writes a sealed copy under a unique
   `tmp/<id>.<uuid>.json` and renames it over the plaintext. Subsequent
   reads go through the AEAD path.
3. A crash between write and rename leaves the plaintext in place; the next
   read retries the migration against the still-unsealed file.
4. Flipping `encrypt_at_rest = false` later (with the key still configured)
   keeps reading already-sealed envelopes: new writes go out plaintext, old
   ones still decode through the still-loaded key.

Three failure modes the AEAD guards against:

- **Swap**: an attacker copies `<id_a>.json` over `<id_b>.json`. The id AAD
  binding makes the tag fail to verify under `id_b`, so the loader rejects
  the envelope.
- **Tamper**: any single-bit flip in the ciphertext trips the Poly1305 tag;
  `load` returns an error mentioning `authentication failed`, never the
  plaintext of a tampered buffer.
- **Truncation**: the loader rejects an envelope that does not at least carry
  the magic and the 12-byte nonce, so a partial write cannot be mistaken for
  a real envelope.

Envelopes never carry a body. `fs_walk::read` returns the envelope bytes;
the loader parses the JSON; the body file is only read when something
actually needs the message text. `FsSpool::load_envelope` reads the envelope
without the body, exactly so `epistle queue show` and the spool check
never print mail.

## `epistle status` (`spool` area)

Two findings, both about on-disk security state:

```
spool   ok    sealed: yes, loose: 0
        ok    encryption: sealed: yes
        ok    permissions: loose: 0
```

- `sealed: yes` reads `encrypt_at_rest` from `[storage]` at the same time
  the spool is opened (so a key-source problem that prevents the spool from
  constructing shows up here as a `fail`, not as a mis-leading `ok`).
- `loose: N` is the number of files and directories whose permissions are
  looser than the bound the spool enforces. The check never modifies the
  filesystem: it walks the tree and counts loose entries, so it observes
  whatever an operator (or an attacker) actually did to the files since
  start-up. If N is non-zero, the area's status drops to `warn`.

The status check reads the envelope through the same loader as the delivery
worker; it cannot be tricked by a sealed envelope that pretends to be
plaintext, and a tampered envelope fails closed with the same error the
worker would see.

## Backups and the spool

A spool that is mid-rewrite is consistent: the write goes to
`tmp/<id>.<uuid>.json` and is renamed only on success. A backup tool that
copies `spool/new/` while the rename is in flight either sees the old
plaintext or the new sealed envelope, never a half-written file (a reader
that opens the half-written filename observes the magic and a truncated
nonce, which fails closed).

Encrypted envelopes are bound to the message id, which is independent of
the key ,  restating what already holds for bodies: a backup of the data
directory remains ciphertext without the key.
