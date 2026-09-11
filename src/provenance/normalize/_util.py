"""Shared helper for building `raw_unmapped`.

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
