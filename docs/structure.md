# Repository structure

This is the map of the source tree and the four rules that keep it a map. If
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
batches split.

## The four rules

1. One folder, one module. A folder that mixes two responsibilities is split
   by responsibility, never by size.
2. A module with more than one file becomes a folder with `mod.rs`.
3. The tests of a module go in `tests/` inside that module, never beside the
   source.
4. `#[path]` is an exception, not a layout. A `#[path]` earns its place by
   pointing at a data file next to the module that reads it. If a new one
   appears, the answer is usually a missing folder.

Rules 3 and 4 describe where the tree is going, not where it is. Today the
unit tests of a module sit beside it as `<module>_tests.rs`, or
`<module>_tests_<topic>.rs` once they grow, and are pulled in with `#[path]`.
That is the layout the batches replace. New code is written in the target
shape; existing code moves when its batch comes.

## Tests

Unit tests live with the code they test. The target layout for a module:

```text example
src/smtp/session/mod.rs              the session
src/smtp/session/tests/mod.rs        declares the session tests
src/smtp/session/tests/queue.rs      one area of the session
```

The `mod.rs` of that `tests/` folder opens with `pub use super::*;`, so a
test file keeps its `use super::*;` unchanged when it moves there.

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
as ```` ```text example ```` like the target layout above. The 500-line
limit per file is checked by `.github/workflows/line-limit.yml`.
