"""EVALUATE: per-subject policy-by-assertion, no engine.

Two kinds of test here, deliberately not blended:

1. Against the two real fixtures — what evaluate() actually decides for
   real evidence, as it stands, today. Both currently come back DENY,
   for two different real reasons (see policy/evaluate.py's module
   docstring) — this is not a bug in the fixtures or the test, it's the
   actual documented finding this build produced.
2. Against constructed EvidenceItem instances — exercising branches
   (a clean ALLOW, an issuer mismatch, a conflicting-builder-identity
   evidence set) that neither real fixture reaches. Each is labeled
   "constructed" in its test name; none of these values are claimed to
   be real evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from provenance.api.demo_bootstrap import seed_from_fixtures
from provenance.models.evidence import EvidenceItem
from provenance.models.provenance import CanonicalProvenance
from provenance.models.verification import VerificationRecord
from provenance.policy.evaluate import evaluate
from provenance.policy.models import PolicyOutcome

FIXTURES = Path(__file__).parent / "fixtures" / "bundles"


def _real_evidence_set(fixture_dir: str) -> list[EvidenceItem]:
    data = seed_from_fixtures([FIXTURES / fixture_dir / "bundle.json"])
    return list(data.records_by_raw_digest.values())


def test_real_ruff_fixture_denied_for_self_hosted_runner():
    decision = evaluate(_real_evidence_set("ruff-0.16.7-linux-x86_64-slsa-v1"))

    assert decision.outcome is PolicyOutcome.DENY
    assert decision.policy_version == "1.0.0"
    assert any("not github-hosted" in r for r in decision.reasons)


def test_real_scorecard_fixture_denied_for_missing_signal():
    decision = evaluate(_real_evidence_set("scorecard-5.5.0-darwin-amd64-slsa-v0.2"))

    assert decision.outcome is PolicyOutcome.DENY
    assert any("cannot confirm" in r for r in decision.reasons)


def _minimal_verification(**overrides) -> VerificationRecord:
    defaults = dict(
        raw_digest="deadbeef",
        signature_verified=True,
        chain_verified=True,
        sct_verified=True,
        tlog_verified=True,
        issuer="https://token.actions.githubusercontent.com",
        verified_at=datetime.now(timezone.utc),
        trust_root="production",
    )
    defaults.update(overrides)
    return VerificationRecord(**defaults)


def _minimal_provenance(**overrides) -> CanonicalProvenance:
    defaults = dict(
        predicate_type="https://slsa.dev/provenance/v1",
        predicate_version="v1",
        adapter_id="slsa_provenance_v1_0",
        adapter_version="1.0.0",
        builder_id="https://github.com/astral-sh/ruff/.github/workflows/release.yml@refs/heads/main",
        build_type="https://actions.github.io/buildtypes/workflow/v1",
    )
    defaults.update(overrides)
    return CanonicalProvenance(**defaults)


def test_constructed_github_hosted_evidence_is_allowed():
    """No real fixture confirms github-hosted — constructed to prove the
    ALLOW branch is reachable and correct, not just theoretical."""
    item = EvidenceItem(
        raw_digest="deadbeef",
        verification=_minimal_verification(),
        provenance=_minimal_provenance(
            raw_unmapped={
                "buildDefinition": {
                    "internalParameters": {"github": {"runner_environment": "github-hosted"}}
                }
            }
        ),
    )

    decision = evaluate([item])

    assert decision.outcome is PolicyOutcome.ALLOW
    assert decision.reasons == []


def test_constructed_issuer_mismatch_is_denied():
    item = EvidenceItem(
        raw_digest="deadbeef",
        verification=_minimal_verification(issuer="https://accounts.example.com"),
        provenance=_minimal_provenance(
            raw_unmapped={
                "buildDefinition": {
                    "internalParameters": {"github": {"runner_environment": "github-hosted"}}
                }
            }
        ),
    )

    decision = evaluate([item])

    assert decision.outcome is PolicyOutcome.DENY
    assert any("acceptable-issuer" in r for r in decision.reasons)


def test_constructed_unverified_evidence_is_denied():
    item = EvidenceItem(
        raw_digest="deadbeef",
        verification=_minimal_verification(signature_verified=False, error="bad signature"),
        provenance=_minimal_provenance(),
    )

    decision = evaluate([item])

    assert decision.outcome is PolicyOutcome.DENY
    assert any("verification did not fully pass" in r for r in decision.reasons)


def test_constructed_conflicting_builder_identities_in_one_set_is_denied():
    """The one genuine evidence-*set*-level check — see module docstring
    on why no real fixture (both singleton sets) reaches this branch."""
    item_a = EvidenceItem(
        raw_digest="aaa",
        verification=_minimal_verification(raw_digest="aaa"),
        provenance=_minimal_provenance(
            raw_unmapped={
                "buildDefinition": {
                    "internalParameters": {"github": {"runner_environment": "github-hosted"}}
                }
            }
        ),
    )
    item_b = EvidenceItem(
        raw_digest="bbb",
        verification=_minimal_verification(raw_digest="bbb"),
        provenance=_minimal_provenance(
            builder_id=(
                "https://github.com/slsa-framework/slsa-github-generator/"
                ".github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0"
            )
        ),
    )

    decision = evaluate([item_a, item_b])

    assert decision.outcome is PolicyOutcome.DENY
    assert any("disagrees on builder identity" in r for r in decision.reasons)


def test_empty_evidence_set_is_denied():
    decision = evaluate([])
    assert decision.outcome is PolicyOutcome.DENY
    assert decision.reasons == ["no evidence for this artifact"]
