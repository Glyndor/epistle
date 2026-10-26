#!/usr/bin/env python3
"""Refuse a workflow tree that leaves a check required on develop without a
`merge_group` trigger, and refuse any other workflow that carries one.

The `protect-develop` ruleset can run a merge queue. In a queue GitHub fires
`merge_group` with `types: [checks_requested]` on a temporary branch
`gh-readonly-queue/develop/pr-<N>-<sha>`, and every required check has to be
reported on that event or the entry waits for a check that never comes and is
dropped at the queue timeout. `paths:` and `branches:` filters do not apply to
`merge_group`, so a workflow that lists only `pull_request` reports nothing
there.

A required check is named `<caller job id> / <reusable job name>`. REQUIRED
below lists the seven checks the ruleset requires, each with the reusable that
holds the job. For each one the scan finds the caller workflow whose job has
that id and `uses:` that reusable, and demands `merge_group` in its `on:`
(with `checks_requested` in `types:` when `types:` is present). It also checks
that the reusable really has a job with that `name:`, so a rename that the
ruleset has not followed is reported here and not by a hanging queue.

The other direction: a workflow that carries `merge_group` without calling one
of those reusables would run inside the queue for nothing (release.yml holds
publishing secrets), so it is refused too.

Usage: check_merge_group_triggers.py [repo-root]
Writes one `::error file=<path>::...` line per violation and exits 1.
"""
import glob
import os
import sys

import yaml

# (caller job id, reusable job name) -> reusable file that must hold the job.
REQUIRED = {
    ("rust", "Format & lint"): "reusable-rust-ci.yml",
    ("rust", "Test"): "reusable-rust-ci.yml",
    ("rust", "Coverage"): "reusable-rust-ci.yml",
    ("dco", "Signed-off-by present on every commit"): "reusable-dco.yml",
    ("line-limit", "line limit"): "reusable-line-limit.yml",
    ("debian", "dpkg-buildpackage"): "reusable-rust-debian.yml",
    ("sbom-and-licenses", "SBOM and license attribution"): "reusable-rust-supply-chain.yml",
}


def triggers(spec):
    """The parsed `on:` block as a dict. PyYAML reads the key `on` as True."""
    on = spec.get("on", spec.get(True))
    if isinstance(on, dict):
        return on
    if isinstance(on, str):
        return {on: {}}
    if isinstance(on, list):
        return {item: {} for item in on}
    return {}


def merge_group_cfg(on):
    """The `merge_group` block, `{}` for a bare one, None when absent."""
    if "merge_group" not in on:
        return None
    cfg = on["merge_group"]
    return cfg if isinstance(cfg, dict) else {}


def has_checks_requested(cfg):
    """True when `types:` is absent (every type) or lists `checks_requested`."""
    types = cfg.get("types")
    if types is None:
        return True
    if isinstance(types, str):
        return types == "checks_requested"
    return isinstance(types, list) and "checks_requested" in types


def load(root):
    """Parse every workflow; a file that does not parse is warned and skipped."""
    parsed = {}
    pattern = os.path.join(root, ".github", "workflows", "*.y*ml")
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path) as fh:
                spec = yaml.safe_load(fh)
        except yaml.YAMLError as err:
            print(f"::warning file={path}::skipped: YAML parse error: {err}")
            continue
        if isinstance(spec, dict):
            parsed[path] = spec
    return parsed


def job_names(spec):
    jobs = spec.get("jobs")
    if not isinstance(jobs, dict):
        return set()
    return {j["name"] for j in jobs.values() if isinstance(j, dict) and isinstance(j.get("name"), str)}


def find_violations(parsed):
    """Return (violations, emitter paths). Violations are (path, message)."""
    violations = []
    emitters = set()
    by_base = {os.path.basename(p): s for p, s in parsed.items()}
    callers = {}
    for path, spec in parsed.items():
        if os.path.basename(path).startswith("reusable-"):
            continue
        jobs = spec.get("jobs")
        if not isinstance(jobs, dict):
            continue
        for job_id, job in jobs.items():
            uses = job.get("uses") if isinstance(job, dict) else None
            if isinstance(uses, str) and uses.startswith("./"):
                callers.setdefault((job_id, os.path.basename(uses)), []).append(path)

    for (job_id, inner), reusable in sorted(REQUIRED.items()):
        check = f"{job_id} / {inner}"
        paths = callers.get((job_id, reusable), [])
        if not paths:
            violations.append((".github/workflows", f"required check `{check}` has no caller: no non-reusable workflow has a job `{job_id}` that uses ./.github/workflows/{reusable}"))
            continue
        if reusable not in by_base or inner not in job_names(by_base[reusable]):
            violations.append((f".github/workflows/{reusable}", f"required check `{check}` is not emitted: {reusable} has no job named `{inner}`"))
        for path in paths:
            emitters.add(path)
            cfg = merge_group_cfg(triggers(parsed[path]))
            if cfg is None:
                violations.append((path, f"`{check}` is required on develop but this workflow has no `merge_group` trigger; the merge queue would wait for it forever"))
            elif not has_checks_requested(cfg):
                violations.append((path, f"`{check}` is required on develop but `merge_group` here has `types: {cfg.get('types')!r}` without `checks_requested`"))

    for path, spec in parsed.items():
        if path not in emitters and merge_group_cfg(triggers(spec)) is not None:
            violations.append((path, "carries `merge_group` but emits no check required on develop; it would run inside the queue for nothing. Remove the trigger"))
    return violations, emitters


def main(argv):
    root = argv[1] if len(argv) > 1 else "."
    parsed = load(root)
    violations, emitters = find_violations(parsed)
    for path, msg in violations:
        print(f"::error file={path}::{msg}")
    if violations:
        return 1
    if not emitters:
        print("::error::merge-group-triggers: scanned no emitting workflow; the scan proves nothing")
        return 1
    print("merge-group-triggers: every required check has a caller triggered on `merge_group`, and no other workflow carries the trigger.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
