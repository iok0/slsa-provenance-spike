"""Response shape for the /v1/ EXPOSE endpoint.

Carries the trust decision now — see provenance.policy.evaluate — plus
the same evidence items EVALUATE consumed to reach it, so a consumer
doesn't have to trust the decision blindly: the facts it was computed
from are right there.
"""

from __future__ import annotations

from pydantic import BaseModel

from provenance.models.artifact import ArtifactRef
from provenance.models.evidence import EvidenceItem
from provenance.policy.models import Decision


class ProvenanceResponse(BaseModel):
    artifact: ArtifactRef

    association_basis: str
    """Which digest matched — trivial today (file digests only, one
    fixed level), becomes meaningful once OCI index-vs-per-platform-
    manifest matching is real (see associate.py's docstring)."""

    provenance_records: list[EvidenceItem]
    """A list, not a single record — provenance cardinality (1:1 vs
    1:many per artifact) is an open question the README names rather
    than resolves; returning a list doesn't presuppose an answer by
    picking a "primary" record when there's more than one."""

    trust_decision: Decision
    """Evaluated over the full `provenance_records` list above (the
    evidence set), not per-record — see policy.evaluate's docstring."""
