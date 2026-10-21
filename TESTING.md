# Testing

How the suite is put together, the full test list, and mutation-testing results. DESIGN.md
quotes the tests that matter for the demo; this is the rest.

## Real vs. constructed evidence

Every test runs against one of two kinds of input, never a blend:

- **The two real fixtures** in `tests/fixtures/bundles/` - ruff 0.16.7 (SLSA v1.0,
  `attest-build-provenance`) and scorecard 5.5.0 (SLSA v0.2, slsa-github-generator), captured
  as-is with a `meta.json` sidecar recording where each came from. These say what the code
  actually does on real evidence today.
- **Constructed inputs** - predicates, `VerificationRecord`s, cert claims, store layouts - for
  branches neither real fixture reaches (a clean ALLOW, an issuer mismatch, a predicate that
  contradicts its cert, ...). Policy tests built this way are named `test_constructed_*`, so
  nothing constructed is passed off as real.

Plus one unit test that builds a throwaway self-signed cert, to check that identity and cert
claims come back `None` (absent), not empty strings, when the Fulcio extensions are missing.

The real-fixture verification tests fetch the live TUF trust root, so they need the network -
see DESIGN.md's "A present risk" section.

## Full suite (58 tests)

```
tests/test_api.py::test_get_provenance_for_known_ruff_artifact PASSED
tests/test_api.py::test_get_provenance_for_known_scorecard_artifact PASSED
tests/test_api.py::test_constructed_multi_pipeline_evidence_set_denied_on_builder_disagreement PASSED
tests/test_api.py::test_unknown_digest_for_known_tenant_is_404 PASSED
tests/test_api.py::test_known_digest_wrong_tenant_is_404_not_leaked PASSED
tests/test_normalize.py::test_adapt_v0_2_matches_real_scorecard_fixture PASSED
tests/test_normalize.py::test_adapt_v1_0_matches_real_ruff_fixture PASSED
tests/test_normalize.py::test_v0_2_and_v1_0_converge_on_the_same_canonical_shape PASSED
tests/test_normalize.py::test_unsupported_predicate_type_raises PASSED
tests/test_normalize.py::test_unsupported_v1_0_build_type_raises PASSED
tests/test_normalize.py::test_adapt_v0_2_tolerates_absent_optional_fields[predicate0] PASSED
tests/test_normalize.py::test_adapt_v0_2_tolerates_absent_optional_fields[predicate1] PASSED
tests/test_normalize.py::test_adapt_v0_2_tolerates_absent_optional_fields[predicate2] PASSED
tests/test_normalize.py::test_adapt_v0_2_material_without_digest_gets_empty_digest PASSED
tests/test_normalize.py::test_adapt_v1_0_tolerates_absent_optional_fields[statement0] PASSED
tests/test_normalize.py::test_adapt_v1_0_tolerates_absent_optional_fields[statement1] PASSED
tests/test_normalize.py::test_adapt_v1_0_source_dependency_without_digest PASSED
tests/test_normalize.py::test_without_paths_removes_only_claimed_leaves_and_copies PASSED
tests/test_normalize.py::test_without_paths_ignores_paths_that_dont_exist[path0] PASSED
tests/test_normalize.py::test_without_paths_ignores_paths_that_dont_exist[path1] PASSED
tests/test_normalize.py::test_without_paths_ignores_paths_that_dont_exist[path2] PASSED
tests/test_policy.py::test_real_ruff_fixture_denied_for_self_hosted_runner PASSED
tests/test_policy.py::test_real_scorecard_fixture_denied_for_missing_signal PASSED
tests/test_policy.py::test_constructed_github_hosted_evidence_is_allowed PASSED
tests/test_policy.py::test_constructed_issuer_mismatch_is_denied PASSED
tests/test_policy.py::test_constructed_builder_id_identity_mismatch_is_denied PASSED
tests/test_policy.py::test_constructed_unknown_builder_is_denied PASSED
tests/test_policy.py::test_constructed_builder_below_required_level_is_denied PASSED
tests/test_policy.py::test_constructed_unverified_evidence_is_denied PASSED
tests/test_policy.py::test_constructed_conflicting_builder_identities_in_one_set_is_denied PASSED
tests/test_policy.py::test_empty_evidence_set_is_denied PASSED
tests/test_policy.py::test_constructed_cert_runner_claim_alone_is_enough_to_allow PASSED
tests/test_policy.py::test_constructed_predicate_runner_contradicting_cert_is_denied PASSED
tests/test_policy.py::test_constructed_cert_runner_claim_without_signer_claims_is_not_used PASSED
tests/test_policy.py::test_constructed_reusable_workflow_runner_claims_are_not_used[predicate_github_hosted] PASSED
tests/test_policy.py::test_constructed_reusable_workflow_runner_claims_are_not_used[predicate_self_hosted] PASSED
tests/test_policy.py::test_constructed_predicate_source_contradicting_cert_is_denied[source_repo] PASSED
tests/test_policy.py::test_constructed_predicate_source_contradicting_cert_is_denied[source_revision] PASSED
tests/test_raw_store_and_verify.py::test_put_is_content_addressed_and_idempotent PASSED
tests/test_raw_store_and_verify.py::test_store_creates_missing_parent_directories PASSED
tests/test_raw_store_and_verify.py::test_on_disk_layout_is_stable PASSED
tests/test_raw_store_and_verify.py::test_put_into_an_existing_fan_out_directory PASSED
tests/test_raw_store_and_verify.py::test_get_unknown_digest_raises_key_error_naming_it PASSED
tests/test_raw_store_and_verify.py::test_verify_from_raw_succeeds_on_real_bundle PASSED
tests/test_raw_store_and_verify.py::test_verify_from_raw_succeeds_on_second_real_bundle_different_slsa_version PASSED
tests/test_raw_store_and_verify.py::test_byte_flip_breaks_verification PASSED
tests/test_raw_store_and_verify.py::test_offline_flag_reaches_trust_root_and_is_recorded[kwargs0-False-production] PASSED
tests/test_raw_store_and_verify.py::test_offline_flag_reaches_trust_root_and_is_recorded[kwargs1-True-production-offline] PASSED
tests/test_verification_record.py::test_fully_verified_when_every_check_passed PASSED
tests/test_verification_record.py::test_not_fully_verified_if_any_one_check_did_not_pass[signature_verified-False] PASSED
tests/test_verification_record.py::test_not_fully_verified_if_any_one_check_did_not_pass[signature_verified-None] PASSED
tests/test_verification_record.py::test_not_fully_verified_if_any_one_check_did_not_pass[chain_verified-False] PASSED
tests/test_verification_record.py::test_not_fully_verified_if_any_one_check_did_not_pass[chain_verified-None] PASSED
tests/test_verification_record.py::test_not_fully_verified_if_any_one_check_did_not_pass[sct_verified-False] PASSED
tests/test_verification_record.py::test_not_fully_verified_if_any_one_check_did_not_pass[sct_verified-None] PASSED
tests/test_verification_record.py::test_not_fully_verified_if_any_one_check_did_not_pass[tlog_verified-False] PASSED
tests/test_verification_record.py::test_not_fully_verified_if_any_one_check_did_not_pass[tlog_verified-None] PASSED
tests/test_verifier.py::test_extract_identity_is_none_for_cert_without_fulcio_extensions PASSED

============================== 58 passed in ~9s ==============================
```

## Mutation testing

`mutmut`, configured in `pyproject.toml`. Run by hand, not in CI:

```
uv run pytest             # first: caches the TUF trust root that mutant runs reuse offline
rm -rf mutants && uv run mutmut run
uv run mutmut results     # list survivors; `uv run mutmut show <name>` for a diff
```

`tests/conftest.py` forces the trust-root fetch offline under mutmut, so a mutant run needs the
cache a plain online `pytest` run leaves behind. Clear `mutants/` before each run: mutmut's
incremental cache skips mutants of source functions that haven't changed, so a test-only change
otherwise isn't scored against them.

Last full run (policy `1.1.0`, v0.2 adapter `1.1.0` normalizing `source_repo`): 622 mutants,
565 killed, 57 survived. Every survivor has been triaged; none changes an allow/deny decision
or a verification result, and none is in the cert cross-check, runner-selection or
`source_repo` normalization logic. Re-triage only survivors outside these groups:

- **Equivalent (17)** - no test can tell them apart from the original: `rsplit("/", 1)[-1]`
  vs `[+1]` or no maxsplit (`predicate_version`), `split("@", 1)` vs no or a larger maxsplit
  (`strip_git_ref`), dropping an explicit `=None` that is already the model default, the
  temp-file suffix in `RawEnvelopeStore.put`, `None` vs `""` as a not-a-dict sentinel in
  `without_paths`, and in `verifier.py` an always-true `if uris` and dropping `asn1Spec` (DER
  is self-tagged).
- **Import-time only (1)** - `_fulcio_oid` in `verifier.py` only runs to build module
  constants, at import, before mutmut switches a mutant on.
- **Message and label text (33)** - denial reasons in `policy/evaluate.py` (including whether
  the "cannot confirm" reason mentions the reusable-workflow signer), exception messages in
  `normalize/`, and the FastAPI app title. Human-facing wording; pinning it would make tests
  brittle for little value.
- **Demo bootstrap (5)** - `.get` defaults the real fixtures never reach, and `store=None`,
  which survives because nothing reads `DemoData.store`.
- **`strip_git_ref`: `split` vs `rsplit` (1)** - they differ only for a URI containing two
  `@`s, which GitHub URIs never do. Neither is right in general: `split` mangles a URI with
  userinfo and a ref (`user@host/repo@ref`), `rsplit` one with userinfo and no ref. The fix is
  to parse the URI rather than split on `@`. Known, not fixed.
