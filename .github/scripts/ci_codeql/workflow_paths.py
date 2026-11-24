"""The `paths:` filter of a workflow, read the way GitHub reads it, judged against what the compiler read.

A workflow that watches the whole product (the end-to-end run, the upgrade test, the container build, the
database tests) is triggered by a change to `src/**` and not by one to the tests. A path filter is a list of
patterns in order: a pattern with `!` removes what the ones before matched, a pattern after it can bring
it back, and the last pattern that matches a file decides. `*` is any run of characters but `/`, `**` is any
run including `/`, `?` is one character but `/`.

The check that matters is the one that fails closed: a file the production build reads and the filter does
not match is a change that skips a workflow it should run.
"""

import re

import ci_yaml


def to_regex(pattern):
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


def matches(patterns, path):
    """True when the last pattern of the filter that matches `path` is not a negation, and one matches."""
    decided = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        if to_regex(pattern[1:] if negated else pattern).fullmatch(path):
            decided = not negated
    return decided


def filters(workflow_path):
    """{event: patterns} for the events of the workflow that have a `paths` filter."""
    on = ci_yaml.load(workflow_path)[True]
    if not isinstance(on, dict):
        return {}
    return {event: value["paths"] for event, value in on.items() if isinstance(value, dict) and "paths" in value}


def missed(workflow_path, production):
    """{event: sorted production files the filter of that event does not match} for a workflow that must see them all."""
    found = {}
    events = filters(workflow_path)
    if not events:
        raise ValueError(f"{workflow_path} has no paths filter to judge")
    for event, patterns in events.items():
        found[event] = sorted(f for f in production if not matches(patterns, f))
    return found
