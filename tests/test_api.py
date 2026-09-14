"""EXPOSE end-to-end: the /v1/ API over the two real fixtures.

Also the only place associate() gets exercised — deliberately not a
dedicated test module for it (see associate.py's docstring: "not a
subsystem with its own tests").
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from provenance.api.app import create_app
from provenance.api.demo_bootstrap import DemoData, seed_from_fixtures

FIXTURES = Path(__file__).parent / "fixtures" / "bundles"

RUFF_DIGEST = "sha256:73894c7b7c9a53fd66ed715eb3a1ec65077f316328e377057a98bdb7fcba0326"
SCORECARD_DIGEST = "sha256:979487ca20e726f6a4d2bd63a0a4c544184f589724b3d12d2ba8d0ea80889063"


def _seeded_data() -> DemoData:
    return seed_from_fixtures(
        [
            FIXTURES / "ruff-0.16.7-linux-x86_64-slsa-v1" / "bundle.json",
            FIXTURES / "scorecard-5.5.0-darwin-amd64-slsa-v0.2" / "bundle.json",
        ]
    )


def _client() -> TestClient:
    return TestClient(create_app(_seeded_data()))


def test_get_provenance_for_known_ruff_artifact():
    resp = _client().get(f"/v1/provenance/acme/{RUFF_DIGEST}")
    assert resp.status_code == 200
    body = resp.json()

    assert body["artifact"] == {
        "tenant_id": "acme",
        "repo": "acme-tools",
        "format_namespace": None,
        "package": "ruff",
        "version": "0.16.7",
        "file": "ruff-x86_64-unknown-linux-gnu.tar.gz",
    }
    assert body["association_basis"] == RUFF_DIGEST

    assert len(body["provenance_records"]) == 1
    record = body["provenance_records"][0]
    assert record["verification"]["signature_verified"] is True
    assert record["provenance"]["predicate_type"] == "https://slsa.dev/provenance/v1"
    assert record["provenance"]["source_repo"] == "https://github.com/astral-sh/ruff"

    # See policy/evaluate.py's module docstring: this is a real, decided
    # DENY (self-hosted runner), not a placeholder or a bug.
    assert body["trust_decision"]["outcome"] == "DENY"
    assert any("not github-hosted" in r for r in body["trust_decision"]["reasons"])


def test_get_provenance_for_known_scorecard_artifact():
    resp = _client().get(f"/v1/provenance/acme/{SCORECARD_DIGEST}")
    assert resp.status_code == 200
    body = resp.json()

    assert body["artifact"]["package"] == "scorecard"
    assert len(body["provenance_records"]) == 1
    record = body["provenance_records"][0]
    assert record["verification"]["signature_verified"] is True
    assert record["provenance"]["predicate_type"] == "https://slsa.dev/provenance/v0.2"

    # Denied for a different real reason than ruff's — v0.2 exposes no
    # runner-environment signal at all, so it can't be confirmed either
    # way (see policy/evaluate.py).
    assert body["trust_decision"]["outcome"] == "DENY"
    assert any("cannot confirm" in r for r in body["trust_decision"]["reasons"])


def test_constructed_multi_pipeline_evidence_set_denied_on_builder_disagreement():
    """Two real, differently-normalized records (v1.0 + v0.2) under one
    shared artifact digest — exercising the fan-out (subject_index holding
    >1 raw_digest, EXPOSE aggregating >1 record) that no other test here
    reaches, since both real fixtures are otherwise singleton evidence sets.

    Constructed by aliasing: scorecard's raw_digest is appended onto
    ruff's subject-index entry, so this doesn't claim scorecard's real
    artifact was actually attested by two pipelines — it simulates that
    scenario using two real, unmodified records so evaluate()'s
    builder-identity-disagreement check (already unit-tested in isolation
    in test_policy.py) is also proven reachable end-to-end through the
    actual route.
    """
    data = _seeded_data()
    data.subject_index[RUFF_DIGEST] = (
        data.subject_index[RUFF_DIGEST] + data.subject_index[SCORECARD_DIGEST]
    )
    client = TestClient(create_app(data))

    resp = client.get(f"/v1/provenance/acme/{RUFF_DIGEST}")
    assert resp.status_code == 200
    body = resp.json()

    assert len(body["provenance_records"]) == 2
    predicate_types = {r["provenance"]["predicate_type"] for r in body["provenance_records"]}
    assert predicate_types == {
        "https://slsa.dev/provenance/v1",
        "https://slsa.dev/provenance/v0.2",
    }

    assert body["trust_decision"]["outcome"] == "DENY"
    assert any(
        "disagrees on builder identity" in r for r in body["trust_decision"]["reasons"]
    )


def test_unknown_digest_for_known_tenant_is_404():
    resp = _client().get("/v1/provenance/acme/sha256:" + "0" * 64)
    assert resp.status_code == 404


def test_known_digest_wrong_tenant_is_404_not_leaked():
    """The tenant-scoping property associate.py's docstring names as a
    security boundary, not just identity-resolution correctness: a real
    digest existing for a *different* tenant must not leak here."""
    resp = _client().get(f"/v1/provenance/some-other-tenant/{RUFF_DIGEST}")
    assert resp.status_code == 404
