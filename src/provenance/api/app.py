"""EXPOSE: the /v1/ provenance API.

`create_app` takes already-seeded data (see demo_bootstrap.py) rather
than seeding itself — the app factory has no filesystem/fixture coupling;
whoever wires up the process decides what to seed it with.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

from provenance.api.demo_bootstrap import DemoData
from provenance.api.models import ProvenanceResponse
from provenance.associate import associate
from provenance.policy.evaluate import evaluate


def create_app(data: DemoData) -> FastAPI:
    app = FastAPI(title="Provenance Ingestion Spike")

    @app.get(
        "/v1/provenance/{tenant_id}/{digest}",
        response_model=ProvenanceResponse,
    )
    def get_provenance(tenant_id: str, digest: str) -> ProvenanceResponse:
        artifact = associate(digest, tenant_id)
        if artifact is None:
            raise HTTPException(
                status_code=404,
                detail=f"no artifact for tenant={tenant_id!r} digest={digest!r}",
            )

        evidence_set = [
            data.records_by_raw_digest[raw_digest]
            for raw_digest in data.subject_index.get(digest, [])
        ]

        return ProvenanceResponse(
            artifact=artifact,
            association_basis=digest,
            provenance_records=evidence_set,
            trust_decision=evaluate(evidence_set),
        )

    return app
