"""Dispatch to the right versioned adapter by `predicateType`.

Deliberately exact string match, not a version-range parser — the two
real predicateType strings pinned here are `.../provenance/v0.2` and
`.../provenance/v1` (not `.../v1.0` — see v1_0.py's docstring). Any other
predicateType raises rather than guessing which adapter is "close enough."
"""

from __future__ import annotations

from typing import Any

from provenance.models.provenance import CanonicalProvenance
from provenance.normalize import v0_2, v1_0
from provenance.normalize.statement import UnsupportedEnvelopeShape, statement_from_raw

__all__ = [
    "UnsupportedEnvelopeShape",
    "UnsupportedPredicateType",
    "normalize_from_raw",
    "statement_from_raw",
]

_ADAPTERS = {
    "https://slsa.dev/provenance/v0.2": v0_2.adapt,
    "https://slsa.dev/provenance/v1": v1_0.adapt,
}


class UnsupportedPredicateType(ValueError):
    """A predicateType with no registered adapter."""


def normalize_from_raw(raw_bytes: bytes) -> CanonicalProvenance:
    """Decode raw envelope bytes and normalize into the canonical model.

    Independent of verification (see statement.py) — reads the same raw
    bytes the raw store hands back, not a caller-held copy.
    """
    statement: dict[str, Any] = statement_from_raw(raw_bytes)
    predicate_type = statement["predicateType"]
    adapter = _ADAPTERS.get(predicate_type)
    if adapter is None:
        raise UnsupportedPredicateType(
            f"no adapter registered for predicateType {predicate_type!r}"
        )
    return adapter(statement)
