"""Deliverable 3/4: versioned normalizer, pinned against real fixtures.

Every expected value below was read directly off the decoded predicate of
the real fixture it tests — not off SPIKE's speculative field table — per
the "don't invent, follow the examples" instruction this was built under.
See normalize/v0_2.py and normalize/v1_0.py's docstrings for the exact
JSON paths and the two corrections found only by looking at the bytes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from provenance.normalize import UnsupportedPredicateType, normalize_from_raw
from provenance.normalize.v1_0 import UnsupportedBuildType, adapt as adapt_v1_0

FIXTURES = Path(__file__).parent / "fixtures" / "bundles"


def _load_bundle_bytes(fixture_dir: str) -> bytes:
    return (FIXTURES / fixture_dir / "bundle.json").read_bytes()


def test_adapt_v0_2_matches_real_scorecard_fixture():
    record = normalize_from_raw(
        _load_bundle_bytes("scorecard-5.5.0-darwin-amd64-slsa-v0.2")
    )

    assert record.predicate_type == "https://slsa.dev/provenance/v0.2"
    assert record.predicate_version == "v0.2"
    assert record.adapter_id == "slsa_provenance_v0_2"

    assert record.builder_id == (
        "https://github.com/slsa-framework/slsa-github-generator/"
        ".github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0"
    )
    assert record.build_type == (
        "https://github.com/slsa-framework/slsa-github-generator/generic@v1"
    )
    assert record.source_repo == "git+https://github.com/ossf/scorecard@refs/tags/v5.5.0"
    assert record.source_revision == "c395761df6afe1a69e476bc60a013a94bcbc153f"
    assert record.invocation_id == "24860294948-1"

    # Genuinely absent from the real predicate, not just unextracted.
    assert record.started_at is None
    assert record.finished_at is None

    assert len(record.dependencies) == 1
    assert record.dependencies[0].uri == record.source_repo
    assert record.dependencies[0].digest == {
        "sha1": "c395761df6afe1a69e476bc60a013a94bcbc153f"
    }

    # raw_unmapped keeps what wasn't claimed — the huge GH webhook payload
    # lives here, unclaimed but not lost (see the README's size note).
    assert "environment" in record.raw_unmapped["invocation"]
    assert "github_event_payload" in record.raw_unmapped["invocation"]["environment"]
    assert "completeness" in record.raw_unmapped["metadata"]
    # But what *was* claimed is gone from raw_unmapped:
    assert "builder" not in record.raw_unmapped
    assert "buildType" not in record.raw_unmapped
    assert "configSource" not in record.raw_unmapped.get("invocation", {})
    assert "buildInvocationID" not in record.raw_unmapped.get("metadata", {})
    assert "materials" not in record.raw_unmapped


def test_adapt_v1_0_matches_real_ruff_fixture():
    record = normalize_from_raw(
        _load_bundle_bytes("ruff-0.16.7-linux-x86_64-slsa-v1")
    )

    assert record.predicate_type == "https://slsa.dev/provenance/v1"
    assert record.predicate_version == "v1"  # not "v1.0" — see module docstring
    assert record.adapter_id == "slsa_provenance_v1_0"

    assert record.builder_id == (
        "https://github.com/astral-sh/ruff/.github/workflows/release.yml"
        "@refs/heads/main"
    )
    assert record.build_type == "https://actions.github.io/buildtypes/workflow/v1"
    assert record.source_repo == "https://github.com/astral-sh/ruff"
    assert record.source_revision == "b5dba861cc38e3f7fb4524c9ceba3e01a474ea13"
    assert record.invocation_id == (
        "https://github.com/astral-sh/ruff/actions/runs/34510395395/attempts/1"
    )

    assert record.started_at is None
    assert record.finished_at is None

    assert len(record.dependencies) == 1
    assert record.dependencies[0].uri == "git+https://github.com/astral-sh/ruff@refs/heads/main"
    assert record.dependencies[0].digest == {
        "gitCommit": "b5dba861cc38e3f7fb4524c9ceba3e01a474ea13"
    }

    # internalParameters (GitHub run context) is real, non-huge extra
    # data that isn't claimed by any canonical field.
    assert "github" in record.raw_unmapped["buildDefinition"]["internalParameters"]
    assert "buildType" not in record.raw_unmapped.get("buildDefinition", {})
    assert "externalParameters" not in record.raw_unmapped.get("buildDefinition", {})
    assert "resolvedDependencies" not in record.raw_unmapped.get("buildDefinition", {})
    assert "builder" not in record.raw_unmapped.get("runDetails", {})


def test_v0_2_and_v1_0_converge_on_the_same_canonical_shape():
    """Demo moment 1: two independently-signed real bundles, different
    predicate versions, different builders — same CanonicalProvenance
    shape, semantically equivalent kinds of fact populated on each."""
    v0_2_record = normalize_from_raw(
        _load_bundle_bytes("scorecard-5.5.0-darwin-amd64-slsa-v0.2")
    )
    v1_0_record = normalize_from_raw(
        _load_bundle_bytes("ruff-0.16.7-linux-x86_64-slsa-v1")
    )

    assert type(v0_2_record) is type(v1_0_record)

    for record in (v0_2_record, v1_0_record):
        assert record.builder_id is not None
        assert record.build_type is not None
        assert record.source_repo is not None
        assert record.source_revision is not None
        assert record.invocation_id is not None
        # Not a claim either fixture exercises multi-dependency handling
        # (see Dependency's docstring) — just that the field is populated.
        assert len(record.dependencies) >= 1

    # Different predicate versions, different builders — genuinely
    # independent evidence, not two copies of the same thing converging
    # trivially.
    assert v0_2_record.predicate_version != v1_0_record.predicate_version
    assert v0_2_record.builder_id != v1_0_record.builder_id


def test_unsupported_predicate_type_raises():
    import base64
    import json

    statement = {"predicateType": "https://example.com/not-slsa/v9", "predicate": {}}
    envelope = {
        "dsseEnvelope": {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
        }
    }
    with pytest.raises(UnsupportedPredicateType):
        normalize_from_raw(json.dumps(envelope).encode())


def test_unsupported_v1_0_build_type_raises():
    statement = {
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://example.com/some-other-builder/v1",
                "externalParameters": {},
                "resolvedDependencies": [],
            },
            "runDetails": {"builder": {"id": "x"}, "metadata": {}},
        },
    }
    with pytest.raises(UnsupportedBuildType):
        adapt_v1_0(statement)
