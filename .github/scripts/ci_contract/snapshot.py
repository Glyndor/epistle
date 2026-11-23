#!/usr/bin/env python3
"""Rewrite the reference copy of the CI files from the tree, for a change made on purpose."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ci_contract.contract as contract  # noqa: E402

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[3]
    contract.write_all(root)
    print(f"wrote {len(contract.FILES)} files under {contract.FOLDER}")
