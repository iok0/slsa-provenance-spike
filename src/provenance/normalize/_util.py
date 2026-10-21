"""Shared helpers: building `raw_unmapped`, and stripping a git URI's ref.

Not a general-purpose deep-diff tool — just enough to remove the exact
leaf keys an adapter claimed, so what's left is "everything this adapter
didn't map," which is raw_unmapped's whole job (see
CanonicalProvenance.raw_unmapped's docstring: a debugging aid, not the
completeness guarantee).
"""

from __future__ import annotations

import copy
from collections.abc import Sequence
from typing import Any


def without_paths(obj: dict[str, Any], paths: Sequence[Sequence[str]]) -> dict[str, Any]:
    """Deep-copy `obj` and delete the leaf key at the end of each path.

    Missing intermediate keys are ignored (nothing to delete). Does not
    prune now-empty parent dicts — an empty `{"invocation": {}}` left
    behind is more honest than silently removing structure the adapter
    never claimed to model.
    """
    result = copy.deepcopy(obj)
    for path in paths:
        *parents, leaf = path
        node = result
        for key in parents:
            if not isinstance(node, dict) or key not in node:
                node = None
                break
            node = node[key]
        if isinstance(node, dict):
            node.pop(leaf, None)
    return result


def strip_git_ref(uri: str) -> str:
    """"git+https://github.com/astral-sh/ruff@refs/heads/main" ->
    "https://github.com/astral-sh/ruff" — exact-match only, see v1_0.py's
    module docstring on what this does not normalize. Shared by the
    adapters to put `source_repo` in its canonical form."""
    uri = uri.removeprefix("git+")
    return uri.split("@", 1)[0]
