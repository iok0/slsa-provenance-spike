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

import pytest

from provenance.api.demo_bootstrap import seed_from_fixtures
from provenance.models.evidence import EvidenceItem
from provenance.models.provenance import CanonicalProvenance
from provenance.models.verification import CertClaims, VerificationRecord
from provenance.policy import evaluate as evaluate_module
from provenance.policy.evaluate import evaluate
from provenance.policy.models import PolicyOutcome

FIXTURES = Path(__file__).parent / "fixtures" / "bundles"


def _real_evidence_set(fixture_dir: str) -> list[EvidenceItem]:
    data = seed_from_fixtures([FIXTURES / fixture_dir / "bundle.json"])
    return list(data.records_by_raw_digest.values())


def test_real_ruff_fixture_denied_for_self_hosted_runner():
    decision = evaluate(_real_evidence_set("ruff-0.16.7-linux-x86_64-slsa-v1"))

    assert decision.policy_version == "1.2.0"
    # One reason only: the predicate agrees with its cert on runner,
    # source repo and revision, so no contradiction is raised — and the
    # denial rests on the cert's runner claim, not ruff's own predicate.
    [reason] = decision.reasons
    assert decision.outcome is PolicyOutcome.DENY
    assert "not github-hosted (per the Fulcio cert)" in reason


def test_real_scorecard_fixture_denied_for_missing_signal():
    decision = evaluate(_real_evidence_set("scorecard-5.5.0-darwin-amd64-slsa-v0.2"))

    # The cert says github-hosted, but it was requested by
    # slsa-github-generator's reusable workflow, so it describes the
    # generator's job, not the build: still cannot confirm. The predicate's
    # source_repo agrees with the cert (no contradiction reason).
    [reason] = decision.reasons
    assert decision.outcome is PolicyOutcome.DENY
    assert "cannot confirm" in reason
    assert "reusable workflow" in reason


def _minimal_verification(**overrides) -> VerificationRecord:
    defaults = dict(
        raw_digest="deadbeef",
        signature_verified=True,
        chain_verified=True,
        sct_verified=True,
        tlog_verified=True,
        issuer="https://token.actions.githubusercontent.com",
        # Matches _minimal_provenance's default builder_id — the identity
        # the signature actually attests to. Override both together when a
        # test needs a different builder; a mismatch is what
        # test_constructed_builder_id_identity_mismatch_is_denied exercises
        # on purpose.
        identity="https://github.com/astral-sh/ruff/.github/workflows/release.yml@refs/heads/main",
        verified_at=datetime.now(timezone.utc),
        trust_root="production",
    )
    defaults.update(overrides)
    return VerificationRecord(**defaults)


_RUFF_WORKFLOW = "https://github.com/astral-sh/ruff/.github/workflows/release.yml@refs/heads/main"


def _calling_workflow_claims(**overrides) -> CertClaims:
    """Cert claims shaped like attest-build-provenance's: the signer is the
    calling workflow itself (.9 == .18), so its runner claim covers the
    build job."""
    defaults = dict(
        build_signer_uri=_RUFF_WORKFLOW,
        build_config_uri=_RUFF_WORKFLOW,
        runner_environment="github-hosted",
        source_repo_uri="https://github.com/astral-sh/ruff",
        source_repo_digest="b5dba861cc38e3f7fb4524c9ceba3e01a474ea13",
    )
    defaults.update(overrides)
    return CertClaims(**defaults)


def _predicate_runner(runner_environment: str) -> dict:
    return {
        "buildDefinition": {
            "internalParameters": {"github": {"runner_environment": runner_environment}}
        }
    }


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


def test_constructed_builder_id_identity_mismatch_is_denied():
    """A signer with an acceptable issuer cannot self-assert its way onto
    the builder allowlist by writing someone else's builder_id into its
    own predicate — the signature only proves who signed it, not that
    builder_id is true. Neither real fixture reaches this branch (both
    happen to have identity == builder_id by construction); constructed
    to prove the check actually fires."""
    item = EvidenceItem(
        raw_digest="deadbeef",
        # A real, acceptable-issuer signer — but *not* the identity
        # matching the allow-listed builder_id below.
        verification=_minimal_verification(
            identity="https://github.com/some-other-repo/.github/workflows/ci.yml@refs/heads/main"
        ),
        provenance=_minimal_provenance(),  # builder_id defaults to ruff's allow-listed id
    )

    decision = evaluate([item])

    assert decision.outcome is PolicyOutcome.DENY
    assert any("does not match the verified signing identity" in r for r in decision.reasons)


def test_constructed_unknown_builder_is_denied():
    """A builder that's simply not in the allowlist at all — distinct from
    the identity-mismatch case above (this builder_id does match who
    signed it; it's just nobody this policy has vetted). No real fixture
    reaches this branch — both real builders are allow-listed."""
    unknown_builder_id = "https://github.com/some-org/unvetted-builder/.github/workflows/build.yml@refs/heads/main"
    item = EvidenceItem(
        raw_digest="deadbeef",
        verification=_minimal_verification(identity=unknown_builder_id),
        provenance=_minimal_provenance(builder_id=unknown_builder_id),
    )

    decision = evaluate([item])

    assert decision.outcome is PolicyOutcome.DENY
    assert any("not in builder allowlist" in r for r in decision.reasons)


def test_constructed_builder_below_required_level_is_denied(monkeypatch):
    """An allow-listed builder whose *documented* level is below what's
    required — distinct from the "cannot confirm" branches the real
    fixtures hit, where the level is sufficient but unconfirmed. No real
    allow-listed builder is below the required level today, so this
    temporarily adds one rather than waiting for evaluate.py's allowlist
    to grow a low-level entry."""
    low_level_builder_id = "https://github.com/some-org/level-1-builder/.github/workflows/build.yml@refs/heads/main"
    monkeypatch.setitem(evaluate_module._BUILDER_ALLOWLIST, low_level_builder_id, 1)

    item = EvidenceItem(
        raw_digest="deadbeef",
        verification=_minimal_verification(identity=low_level_builder_id),
        provenance=_minimal_provenance(builder_id=low_level_builder_id),
    )

    decision = evaluate([item])

    assert decision.outcome is PolicyOutcome.DENY
    assert any("claims level 1, required 3" in r for r in decision.reasons)


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
    item_b_builder_id = (
        "https://github.com/slsa-framework/slsa-github-generator/"
        ".github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0"
    )
    item_b = EvidenceItem(
        raw_digest="bbb",
        # identity overridden to match item_b's own builder_id override —
        # this test is exercising the evidence-*set*-level disagreement
        # check, not the per-item identity/builder_id check added above.
        verification=_minimal_verification(raw_digest="bbb", identity=item_b_builder_id),
        provenance=_minimal_provenance(builder_id=item_b_builder_id),
    )

    decision = evaluate([item_a, item_b])

    assert decision.outcome is PolicyOutcome.DENY
    assert any("disagrees on builder identity" in r for r in decision.reasons)


def test_empty_evidence_set_is_denied():
    decision = evaluate([])
    assert decision.outcome is PolicyOutcome.DENY
    assert decision.reasons == ["no evidence for this artifact"]


def test_constructed_cert_runner_claim_alone_is_enough_to_allow():
    """The predicate carries no runner signal at all; the cert's, which
    covers the build job here, is what confirms it."""
    item = EvidenceItem(
        raw_digest="deadbeef",
        verification=_minimal_verification(cert_claims=_calling_workflow_claims()),
        provenance=_minimal_provenance(),
    )

    decision = evaluate([item])

    assert decision.outcome is PolicyOutcome.ALLOW
    assert decision.reasons == []


def test_constructed_predicate_runner_contradicting_cert_is_denied():
    """Another step in an attest-build-provenance job holds the same
    id-token and can sign a predicate claiming github-hosted on a
    self-hosted runner. The cert, filled in by Fulcio from GitHub's token,
    can't be talked into agreeing."""
    item = EvidenceItem(
        raw_digest="deadbeef",
        verification=_minimal_verification(
            cert_claims=_calling_workflow_claims(runner_environment="self-hosted")
        ),
        provenance=_minimal_provenance(raw_unmapped=_predicate_runner("github-hosted")),
    )

    decision = evaluate([item])

    assert decision.outcome is PolicyOutcome.DENY
    assert any(
        "predicate runner_environment 'github-hosted' contradicts the Fulcio cert's "
        "'self-hosted'" in r
        for r in decision.reasons
    )
    assert any("not github-hosted (per the Fulcio cert)" in r for r in decision.reasons)


def test_constructed_undecodable_cert_runner_claim_does_not_fall_back_to_predicate():
    """The previous test's cert, but with `.11` unreadable: VERIFY leaves
    the claim None and records why. Without that record, None reads as
    "the cert doesn't say" and the predicate's github-hosted would ALLOW."""
    item = EvidenceItem(
        raw_digest="deadbeef",
        verification=_minimal_verification(
            cert_claims=_calling_workflow_claims(runner_environment=None),
            cert_decode_errors=["1.3.6.1.4.1.57264.1.11: not a DER UTF8String"],
        ),
        provenance=_minimal_provenance(raw_unmapped=_predicate_runner("github-hosted")),
    )

    decision = evaluate([item])

    assert decision.outcome is PolicyOutcome.DENY
    assert decision.reasons == [
        "deadbeef: cert extension(s) present but undecodable, so cert facts can't "
        "be relied on: ['1.3.6.1.4.1.57264.1.11: not a DER UTF8String']"
    ]


def test_constructed_cert_runner_claim_without_signer_claims_is_not_used():
    """A cert with a runner claim but no `.9`/`.18` doesn't say whose job
    the claim describes, so the predicate decides — as in policy 1.0.0."""
    item = EvidenceItem(
        raw_digest="deadbeef",
        verification=_minimal_verification(
            cert_claims=_calling_workflow_claims(build_signer_uri=None, build_config_uri=None)
        ),
        provenance=_minimal_provenance(raw_unmapped=_predicate_runner("self-hosted")),
    )

    decision = evaluate([item])

    assert decision.outcome is PolicyOutcome.DENY
    assert decision.reasons == [
        f"deadbeef: builder {_RUFF_WORKFLOW!r}'s claimed level 3 is documented for "
        "GitHub-hosted runners; this attestation's runner_environment was not "
        "github-hosted (per the provenance predicate)"
    ]


@pytest.mark.parametrize(
    "predicate_runner",
    ["github-hosted", "self-hosted"],
    ids=["predicate_github_hosted", "predicate_self_hosted"],
)
def test_constructed_reusable_workflow_runner_claims_are_not_used(predicate_runner):
    """A reusable workflow's cert describes its own job, not the build — and
    so does a predicate written by a step inside it, self-asserted to boot.
    Neither confirms the build's runner, so the predicate can't fill the gap
    the cert leaves: a github-hosted predicate claim must not ALLOW."""
    item = EvidenceItem(
        raw_digest="deadbeef",
        verification=_minimal_verification(
            cert_claims=_calling_workflow_claims(
                build_config_uri="https://github.com/astral-sh/ruff/.github/workflows/caller.yml@refs/heads/main"
            )
        ),
        provenance=_minimal_provenance(raw_unmapped=_predicate_runner(predicate_runner)),
    )

    decision = evaluate([item])

    assert decision.outcome is PolicyOutcome.DENY
    [reason] = decision.reasons
    assert "cannot confirm" in reason
    assert f"signed by reusable workflow {_RUFF_WORKFLOW!r}" in reason


@pytest.mark.parametrize(
    ("provenance_overrides", "expected"),
    [
        (
            {"source_repo": "https://github.com/someone-else/fork"},
            "predicate source_repo 'https://github.com/someone-else/fork' contradicts "
            "the Fulcio cert's 'https://github.com/astral-sh/ruff'",
        ),
        (
            {"source_revision": "0" * 40},
            f"predicate source_revision {'0' * 40!r} contradicts the Fulcio cert's "
            "'b5dba861cc38e3f7fb4524c9ceba3e01a474ea13'",
        ),
    ],
    ids=["source_repo", "source_revision"],
)
def test_constructed_predicate_source_contradicting_cert_is_denied(
    provenance_overrides, expected
):
    item = EvidenceItem(
        raw_digest="deadbeef",
        verification=_minimal_verification(cert_claims=_calling_workflow_claims()),
        provenance=_minimal_provenance(**provenance_overrides),
    )

    decision = evaluate([item])

    assert decision.outcome is PolicyOutcome.DENY
    assert decision.reasons == [f"deadbeef: {expected}"]
