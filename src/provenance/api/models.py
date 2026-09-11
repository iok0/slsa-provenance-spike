"""Response shapes for the /v1/ EXPOSE endpoint.

Deliberately no `trust_decision` / `policy_version` field yet — EVALUATE
isn't wired (that's the next deliverable, not this one). Adding it later
means adding a field here, not reshaping this response: verification and
normalization are already the exact inputs a policy decision would
consume (see README's per-subject policy input-document design), so this
response already carries what EVALUATE needs, just without EVALUATE
having run over it yet.
"""

from __future__ import annotations

from pydantic import BaseModel

from provenance.models.artifact import ArtifactRef
from provenance.models.provenance import CanonicalProvenance
from provenance.models.verification import VerificationRecord


class ProvenanceRecordEntry(BaseModel):
    raw_digest: str
    verification: VerificationRecord
    provenance: CanonicalProvenance


class ProvenanceResponse(BaseModel):
    artifact: ArtifactRef

    association_basis: str
    """Which digest matched — trivial today (file digests only, one
    fixed level), becomes meaningful once OCI index-vs-per-platform-
    manifest matching is real (see associate.py's docstring)."""

    provenance_records: list[ProvenanceRecordEntry]
    """A list, not a single record — provenance cardinality (1:1 vs
    1:many per artifact) is an open question the README names rather
    than resolves; returning a list doesn't presuppose an answer by
    picking a "primary" record when there's more than one."""
