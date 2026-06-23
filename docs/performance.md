# Performance

epistle handles mail on per-byte, per-message, per-connection paths, so the
work that matters is the work done *per request*: parsing a command line,
rendering a response, persisting a flag change. This page records the hot paths
that have been measured, the allocation and write-amplification reductions made
on them, and how to reproduce the measurements.

The guiding rule is honesty over churn: a path is only changed when the saving
can be named. Several paths audited here were already tight and were left
untouched (see [What was left alone](#what-was-left-alone)).

## Hot paths considered

- **Per-command parsing** — SMTP command/address parsing (`src/smtp`), IMAP
  command parsing (`src/imap/command`). Every connection runs these once per
  line.
- **Per-message response building** — IMAP FETCH/STORE response rendering
  (`src/imap/session/fetchstore.rs`, `src/imap/mailbox.rs`). Runs once per
  message in a result set.
- **Flag persistence** — IMAP STORE writing the `.flags` sidecar
  (`src/imap/mailbox.rs`).
- **Outbound queue + spool** — SRS rewriting, DSN construction, the filesystem
  spool, suppression lookup (`src/queue`, `src/storage/spool.rs`).

## Allocation reductions

### `render_flags` — one allocation per call removed

`src/imap/mailbox.rs`. The flag list of a message is rendered on every
`FETCH FLAGS` and every non-silent `STORE` response. The previous
implementation collected the flag tokens into a `Vec<&str>` and then `join`ed
them into a `String` — two heap allocations per call. It now writes directly
into a single `String` pre-sized to the exact final length (parentheses + token
bytes + separators), so the intermediate `Vec` is gone and the result buffer
never reallocates. The function is allocation-bound at this size, so removing
one of two allocations is a real relative cut.

## Write-amplification reductions

Storage stays crash-safe throughout: every mutating write is still a
`write to a temp file → fsync → atomic rename`. The reductions below remove
writes that produce **no observable change**, never writes that carry
durability.

### No-op STORE skips the sidecar write and the mod-sequence bump

`Snapshot::store_flags` in `src/imap/mailbox.rs`. A STORE that sets a message's
flags to the set it already has is common — clients re-mark `\Seen`, re-apply a
`+FLAGS` that is already present, or issue a `FLAGS` that matches. The previous
code unconditionally:

1. rewrote the `<id>.flags` sidecar (temp file + fsync + rename),
2. advanced the mailbox mod-sequence counter (a counter write), and
3. wrote the per-message mod-sequence sidecar.

That is three disk operations for a change that changes nothing.
`store_flags` now compares the requested flag set against the current one
(order- and duplicate-independent) and, when they match, returns the existing
flags immediately — no disk I/O, no counter advance.

This is not only cheaper but **more correct**: RFC 7162 says a STORE that does
not change the flags must not advance the mod-sequence. No existing behavior
relies on a no-op STORE bumping `MODSEQ`; a STORE that genuinely changes flags
still writes and advances exactly as before.

**Durability is preserved** because the skipped writes only ever applied to a
state that already equals the requested one — there is nothing to make durable.
The crash-safe temp+fsync+rename path is untouched for every real change.

Measured impact (`cargo bench --bench queue -- store_flags`, criterion, release):

| Case | Time |
|---|---|
| `store_flags_change` (real change: sidecar + 2 counter writes) | ~50 µs |
| `store_flags_noop` (same set re-stored, now skipped) | ~7 ns |

The no-op path is roughly four orders of magnitude cheaper because it avoids the
fsync-class syscalls entirely. Numbers are machine-dependent; reproduce locally.

## What was left alone

Reported honestly, these paths were audited and found already tight; changing
them would be churn for no measurable gain:

- **SMTP/IMAP/address parsers** borrow with `split_once`/`rsplit_once`/`strip_*`
  and allocate only the owned fields the parsed command must own. The IMAP
  search parser produces an owned AST; those allocations are intrinsic.
- **`FsSpool::store`** clones the envelope's reverse-path/recipients out of the
  borrowed `AcceptedMessage`, but the path is dominated by two `fsync`s — the
  small-string clones are noise next to millisecond-scale durability syscalls,
  so a borrowing serialize-only envelope would add a parallel type for no
  measurable win.
- **`append`** already skips the `.flags` sidecar entirely when the flag set is
  empty (the common delivered-message case).

## Running the benchmarks

The criterion benches live in `benches/`:

```sh
# All benches.
SQLX_OFFLINE=true cargo bench

# A single group or case (substring-filtered).
SQLX_OFFLINE=true cargo bench --bench queue -- store_flags
SQLX_OFFLINE=true cargo bench --bench parsers -- render_flags

# Just confirm they compile, without running.
SQLX_OFFLINE=true cargo bench --no-run
```

Criterion writes HTML reports under `target/criterion/`. Run a bench once to
establish a baseline, make a change, and run it again — criterion reports the
delta against the stored baseline automatically.

## Flamegraphs

To see where wall-clock time actually goes on a hot path, profile a bench with
[`cargo flamegraph`](https://github.com/flamegraph-rs/flamegraph):

```sh
# One-time: install the subcommand (needs perf on Linux).
cargo install flamegraph

# Profile a single bench binary; --bench keeps criterion from looping forever.
SQLX_OFFLINE=true cargo flamegraph --bench queue -- --bench store_flags

# Opens/writes flamegraph.svg in the working directory.
```

The resulting SVG is interactive: wide frames are where time is spent, so a
storage path dominated by `fsync` shows a wide syscall frame — exactly the cost
the no-op STORE skip removes.

## Profiling pass

The criterion benches above time individual functions in isolation. They do not
show where the wall-clock of a *realistic* message lifecycle goes — a message is
received and parsed, delivered to disk, then read back over IMAP. To profile
that end-to-end shape there is a macro workload at `examples/profile.rs`.

Each iteration drives the real public hot paths against a `tempfile::tempdir()`
store:

1. **Parse** — SMTP `MAIL FROM`/`RCPT TO`, the recipient `Address`, an IMAP
   `UID FETCH`, and the raw header block fed through the `LineDecoder` (the
   per-byte/per-command paths every receive exercises).
2. **Deliver** — `LocalDelivery::deliver_routed` writes one crash-safe `.eml`
   copy (temp file → `fsync` → atomic rename) into the recipient's INBOX.
3. **Read** — `Snapshot::open` scans the mailbox directory, then `read` pulls
   the newest message back, the path a client `FETCH` walks.
4. **Store** — `store_flags(\Seen)` plus `render_flags` on the response (the
   path the no-op-skip and `render_flags` work above touches).

### Running it

```sh
# N messages (default 2000). Use --release for representative timings.
SQLX_OFFLINE=true cargo run --release --example profile -- 2000

# Flamegraph the whole pipeline (writes flamegraph.svg in the cwd).
SQLX_OFFLINE=true cargo flamegraph --example profile -- 2000
```

It prints elapsed wall-time and throughput (msgs/sec) at the end.

### What the pass surfaces

The methodology is qualitative — read the flame widths, do not trust absolute
numbers across machines — but the shape is consistent:

- **Delivery is fsync-bound.** The widest frames sit under
  `LocalDelivery`/`write_sync`, in the `fsync`-class syscalls of the
  temp+fsync+rename write. This is *inherent* durability cost: a message is not
  accepted until it is durable on disk, so the two synchronous writes per
  message are the floor, not waste. Nothing here is "fixable" without weakening
  the crash-safety guarantee.
- **Parsing is allocation-light.** The parse stage is a thin sliver: the SMTP,
  address and IMAP parsers borrow with `split_once`/`strip_*` and the line
  decoder reuses its buffer, so this stage barely registers next to the
  delivery fsyncs (consistent with [What was left alone](#what-was-left-alone)).
- **The snapshot scan grows with the mailbox.** `Snapshot::open` is O(mailbox
  size) — it lists the `new/` directory and sorts the messages. The example
  re-opens a mailbox that grows by one message per iteration, so at large N the
  cumulative `open` cost overtakes delivery and total throughput falls off
  super-linearly. This is the cost a real session pays once per `SELECT`, not
  per message, but the workload makes it visible. The STORE stage benefits
  directly from the no-op skip and the single-allocation `render_flags` covered
  above (see [#237](https://github.com/Glyndor/epistle/issues/237) for the
  `store_flags`/`render_flags` work).

On the development machine the run printed roughly **540 msgs/sec at N=200** —
where delivery fsyncs dominate — falling to about **50 msgs/sec at N=2000** as
the growing per-iteration `Snapshot::open` scan takes over. The absolute figures
are storage- and machine-dependent (an SSD with fast `fsync` shifts them
sharply); reproduce locally and read the flamegraph for the relative shape
rather than the headline number.
