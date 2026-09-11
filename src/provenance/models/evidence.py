"""One piece of evidence about an artifact: verified + normalized.

Shared shape — this is both what the API returns per attestation and
what EVALUATE's input document is built from (see README: normalized
facts + verification result + pointer to raw, per attestation in the
set). One definition, not two near-identical ones.
"""

from __future__ import annotations

from pydantic import BaseModel

from provenance.models.provenance import CanonicalProvenance
from provenance.models.verification import VerificationRecord


class EvidenceItem(BaseModel):
    raw_digest: str
    verification: VerificationRecord
    provenance: CanonicalProvenance
