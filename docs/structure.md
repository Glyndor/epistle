# Repository structure

This is the map of the source tree and the rules that keep it a map. If
something is hard to find, the fix is to move the code, not to widen this
page.

## Where things live

`src/<domain>/` holds one domain. Inside it, a module that needs more than one
file becomes `src/<domain>/<module>/`, with a `mod.rs` and siblings declared
with a plain `mod <sibling>;`. For example:

```text
src/smtp/                 the SMTP protocol: address, command, line, auth, trace
src/smtp/session/         one SMTP session
src/smtp/server/          the listener that accepts connections and drives sessions
src/imap/mailbox/         mailboxes on disk: flags, hierarchy, journal
```

`src/main.rs` is a thin entry point. All server logic is in the library
(`src/lib.rs`), so the integration tests, the benches and the fuzz targets
reach the same code the binary runs.

Many domains still keep dozens of files side by side. The tree is moving to
this shape in batches, tracked in #1211, and those domains are what the
batches split. Moving the product code from `src/` to `internal/`, as the
organisation's layout standard asks, is a separate step that has not been
taken yet.

## The four rules

1. One folder, one module. A folder that mixes two responsibilities is split
   by responsibility, never by size.
2. A module with more than one file becomes a folder with `mod.rs`, and its
   siblings are declared with a plain `mod <sibling>;`.
3. The unit tests of a module live in a sibling file, never in an inline
   `mod tests { ... }` block. `foo.rs` declares
   `#[cfg(test)] #[path = "foo_tests.rs"] mod tests;` and the tests sit in
   `foo_tests.rs` beside it; a `mod.rs` uses `mod_tests.rs`.
4. `#[path]` declares that sibling test module, or reads a data file next to
   the module that uses it. A `#[path]` that splits production code across
   files is a missing folder, and those are the ones the batches remove.

Whether the tests of each module should move into a folder of their own is
an open decision for the maintainer. Until it is taken, rule 3 is the rule.

## Tests

`src/cidr.rs` and `src/cidr_tests.rs` are the shape of rule 3, and so are
`src/metrics/mod.rs` and `src/metrics/tests/base.rs`. Tests that outgrow one
file are split by topic as `<module>_tests_<topic>.rs`, each declared the
same way.

The integration suite is separate: `tests/`, one file per flow, with shared
helpers in `tests/common/` and fixtures in `tests/fixtures/`.

## Naming

A module, its error type and its tests share one stem. A file that has to be
called `<stem>_routes.rs` and `<stem>_queue.rs` to tell its parts apart is
asking to become the folder `<stem>/`.

## What is checked

`tests/repository_paths_exist.rs` reads every path cited in `README.md`,
`CONTRIBUTING.md`, `docs/`, the comments under `src/` and the sources under
`tests/`, and fails on any that does not exist, so a move cannot leave a page
or a comment pointing at nothing. A path that only illustrates a shape is
written with a placeholder (`src/<domain>/`), or inside a block fenced
as ```` ```text example ````. The 500-line limit per file is checked by
`.github/workflows/line-limit.yml`.
