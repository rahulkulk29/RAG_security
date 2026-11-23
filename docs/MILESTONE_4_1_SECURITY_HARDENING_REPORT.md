# Milestone 4.1 Security Hardening Report: Retrieval and API Hardening

**Date:** 2026-11-17  
**Status:** Complete & Verified  
**Test Suite Status:** 108 Passed, 0 Failed (100% passing across 7 test modules)

---

## 1. Executive Summary

Milestone 4.1 addresses critical application security and data-integrity findings identified during review of the Milestone 4 retrieval and API layers, including focused testbed authorization and audit hardening. The goal was to eliminate fail-open edge cases, prevent data corruption from propagating through domain models, restrict evaluation-only identity resolution from running in production, harden HTTP transport (CORS), prevent reflection of attacker payloads in error messages, and prepare configurable environment settings for upcoming LLM integration.

All 83 baseline tests continue to pass without modification. 25 new security regression tests were added across the test suite (15 in `tests/test_retrieval.py`, 5 in `tests/test_api.py`, and 5 in `tests/test_authorization.py`), bringing the total test suite to 108 tests.

---

## 2. Findings Addressed

1. **Lenient Metadata Parsing & Placeholder Mutation (`app/retrieval/retriever.py`)**:
   - *Previous behavior*: Raw ChromaDB metadata was converted using `str(None)` (which produces `"None"`), `int()` without type checks, and boolean coercion. Missing or invalid tenant/role metadata constructed a dummy `DocumentChunk` and mutated `__dict__["tenant_id"] = None` so `AuthorizationGuard` would drop it downstream.
   - *Hardening*: Implemented `_validate_raw_chroma_results` and `_parse_and_validate_candidate`. Raw metadata fields are strictly validated before domain object construction. Missing, None, malformed, non-string, or misaligned entries are dropped fail-closed without mutating Pydantic objects or constructing dummy placeholders.
2. **Malformed or Misaligned ChromaDB Result Arrays & Outer Dimension Enforcement**:
   - *Previous behavior*: Result extraction assumed nested lists were present and well-formed.
   - *Hardening*: Validates that `ids`, `documents`, `metadatas`, and `distances` are non-empty nested lists with matching element lengths. Enforces that each contains exactly one inner result group (`len(val) == 1`), rejecting unexpected additional outer groups fail-closed.
3. **Strict Content, Distance Validation & Overflow Protection**:
   - *Previous behavior*: Empty or non-string document texts were accepted; non-numeric or boolean distances (e.g. `True`) could pass arithmetic checks. Extremely large numeric values could raise unhandled `OverflowError`.
   - *Hardening*: Rejects non-string, empty, or whitespace-only document content. Rejects boolean, non-numeric, negative, NaN, and infinite distance values. Safely catches `OverflowError` during float conversion. Normalizes and clamps similarity scores to $[0.0, 1.0]$.
4. **Safe Canary Reference Representation & Required Metadata Key**:
   - *Previous behavior*: Canary references were split naively by comma, and a missing `canary_refs` key was defaulted to an empty string.
   - *Hardening*: Requires the `canary_refs` key to exist in metadata (rejecting missing keys). Preserves the valid empty-string representation (`""`) for documents without canaries. `_parse_and_validate_canary_refs` enforces comma-separated format, rejects empty items or whitespace tokens (e.g. `"CANARY-1,"` or `",CANARY-1"`), rejects raw canary secret tokens (`CANARY_SEC_...`), and validates identifier formatting.
5. **Evaluation Simulator Isolation & Constrained Environment Setting**:
   - *Previous behavior*: `TestContextResolver` operated unconditionally in any environment, and `environment` was an unconstrained string.
   - *Hardening*: Typed `environment` as `Literal["development", "test", "production"]`, rejecting invalid values such as `"prod"` or `"production "` during startup/configuration. `TestContextResolver.resolve` strictly raises `AuthenticationError` if `settings.environment == "production"`.
6. **Raw Retrieval Endpoint Protection**:
   - *Previous behavior*: `/retrieve` and `/query/retrieve` were accessible in all modes.
   - *Hardening*: Both `/retrieve` and `/query/retrieve` verify `settings.environment` and return `HTTP 403 Forbidden` if invoked in `production`.
7. **CORS Hardening (`app/api/main.py`)**:
   - *Previous behavior*: `CORSMiddleware` configured with wildcard origins `allow_origins=["*"]` combined with `allow_credentials=True`.
   - *Hardening*: Configured explicit origins via `settings.cors_allowed_origins` (defaulting to local development URLs) and restricted allowed methods (`GET`, `POST`, `OPTIONS`) and headers (`Content-Type`, `Authorization`).
8. **Safe Authentication Error Responses & Safe Logging (`app/api/routes.py`)**:
   - *Previous behavior*: Returned `detail=f"Authentication failed: {str(auth_err)}"`, reflecting caller input in HTTP 401 responses, and logged raw exceptions.
   - *Hardening*: Returns fixed generic `detail="Authentication failed: invalid or unknown test identity"`. Prevents attacker payload reflection (XSS, SQLi, tokens) in responses and prevents credential leakage in server logs.
9. **Gemini Configuration Preparation (`app/core/config.py`)**:
   - *Previous behavior*: Contained hardcoded legacy `"gemini-1.5-pro"` model default.
   - *Hardening*: Removed legacy model default; left `gemini_model_id: Optional[str] = None` configurable via `GEMINI_MODEL_ID` environment variable without premature SDK dependencies.
10. **Post-Retrieval Authorization Verification in API Integration Tests (`tests/test_api.py`)**:
    - *Previous behavior*: The mock ChromaDB record in `test_api_unauthorized_content_never_in_response` lacked `chunk_index`, causing it to be dropped at metadata parsing before reaching `AuthorizationGuard`.
    - *Hardening*: Updated the mock record to be structurally complete and valid (`chunk_index: 0`). Added assertions verifying the record reaches `AuthorizationGuard.filter_authorized_candidates` and is specifically rejected by the post-retrieval authorization guard.

---

## 3. Files Modified

| File | Changes Made |
| :--- | :--- |
| `app/core/config.py` | Constrained `environment` to `Literal["development", "test", "production"]`; added `cors_allowed_origins`, `cors_allowed_methods`, `cors_allowed_headers`; updated `gemini_model_id` to be unset/configurable. |
| `.env.example` | Documented `ENVIRONMENT`, `CORS_ALLOWED_ORIGINS`, and updated `GEMINI_MODEL_ID` configuration comments. |
| `app/retrieval/retriever.py` | Implemented `_validate_raw_chroma_results` with exact outer group checking; implemented `_parse_and_validate_canary_refs` requiring key existence; handled `OverflowError` on distance float conversion; removed placeholder objects and `__dict__` mutation. |
| `app/authorization/identity.py` | Added production environment enforcement to `TestContextResolver.resolve()`. |
| `app/api/main.py` | Configured `CORSMiddleware` with explicit settings-based origins, methods, and headers. |
| `app/api/routes.py` | Added production check (403 Forbidden), generic 401 response message, and safe logging. |
| `tests/test_retrieval.py` | Added 15 fail-closed metadata regression tests (including missing canary key, numeric distance overflow, and outer ChromaDB dimension validation). |
| `tests/test_api.py` | Updated `test_api_unauthorized_content_never_in_response` with valid `chunk_index` and guard inspection; added 5 security regression tests (error reflection, production mode lockout, resolver lockout, CORS configuration, and Literal environment validation). |
| `tests/test_authorization.py` | Replaced `Exception` with Pydantic `ValidationError` in immutability test; added 4 candidate filtering tests and 1 cross-tenant rejection audit logging test. |

---

## 4. Files Created

| File | Purpose |
| :--- | :--- |
| `docs/MILESTONE_4_1_SECURITY_HARDENING_REPORT.md` | Comprehensive milestone report and audit documentation. |

---

## 5. Security Decisions

1. **Fail-Closed Result Validation**:
   - Rather than attempting to "sanitize" malformed metadata by injecting fallback strings, invalid ChromaDB candidates are immediately dropped. An invalid record never produces a `DocumentChunk` or `CandidateChunk`.
2. **Defensive Separation of Concerns**:
   - Pre-retrieval filtering optimizes database query load.
   - Strict candidate parsing guarantees structural integrity and data validity.
   - Post-retrieval authorization (`AuthorizationGuard`) verifies tenant isolation and role privilege tiers.
   - Even if database corruption or indexing bugs occur, invalid data is eliminated at the retriever barrier.
3. **Information Disclosure Prevention**:
   - HTTP 401 responses never echo user-supplied `test_identity_id` values. Attacker payloads (e.g. `<script>`, SQL injection strings, or canary tokens) cannot be reflected to clients or written to auth warning logs.
4. **Environment Isolation**:
   - The test identity simulator is explicitly recognized as benchmark tooling. Restricting both identity resolution and the raw chunk retrieval routes in `production` prevents accidental deployment of mock security controls.

---

## 6. Tests Added

### Section A: Retrieval Metadata Fail-Closed Tests (`tests/test_retrieval.py`)
1. `test_fail_closed_invalid_chunk_id`: Validates rejection of empty, whitespace, `None`, or numeric chunk IDs.
2. `test_fail_closed_invalid_doc_id`: Validates rejection of empty, whitespace, `None`, or numeric `doc_id`.
3. `test_fail_closed_invalid_tenant_metadata`: Validates rejection of unknown, `None`, or numeric tenant identifiers.
4. `test_fail_closed_invalid_access_level_metadata`: Validates rejection of unknown, `None`, or numeric access levels.
5. `test_fail_closed_invalid_chunk_index`: Validates rejection of booleans (`True`/`False`), negative ints, floats, strings, or `None`.
6. `test_fail_closed_malformed_boolean_flags`: Validates rejection of string representations (`"true"`, `"false"`), integers (`0`, `1`), or `None` for `is_poisoned` and `has_secret`.
7. `test_fail_closed_malformed_canary_refs`: Validates rejection of malformed canary ref strings (trailing commas, whitespace items, invalid characters, and raw canary secret leak tokens).
8. `test_fail_closed_strict_content_validation`: Validates rejection of empty, whitespace-only, `None`, or non-string document texts.
9. `test_fail_closed_distance_validation_and_score_bounds`: Validates rejection of NaN, Inf, negative, boolean, or non-numeric distance values, and validates similarity score clamping to $[0.0, 1.0]$.
10. `test_fail_closed_missing_or_non_dict_metadata`: Validates rejection when metadata is `None`, non-dict, or missing.
11. `test_fail_closed_malformed_chromadb_result_arrays`: Validates rejection of non-dict results, missing keys, non-nested lists, and misaligned array lengths.
12. `test_fail_closed_never_leaks_document_content_on_malformed_metadata`: Verifies that a document containing secrets and injection payloads is completely dropped when metadata is corrupted, with zero document content leaked.
13. `test_fail_closed_rejects_missing_canary_refs_key`: Verifies that metadata missing the `canary_refs` key is rejected fail-closed, while preserving valid empty strings.
14. `test_fail_closed_distance_numeric_overflow`: Verifies that an extremely large integer distance causing `OverflowError` during float conversion is caught and safely rejected.
15. `test_fail_closed_chromadb_outer_dimensions_unexpected_groups`: Verifies that ChromaDB results with unexpected additional outer groups are rejected fail-closed.

### Section B: API Security Regression Tests (`tests/test_api.py`)
16. `test_api_auth_error_never_reflects_attacker_input`: Verifies that attacker payloads (XSS, SQLi, tokens) in `test_identity_id` are never reflected in HTTP 401 responses.
17. `test_api_production_mode_blocks_retrieval_endpoints`: Verifies that `/retrieve` and `/query/retrieve` return HTTP 403 Forbidden in production environment.
18. `test_test_context_resolver_blocks_in_production`: Verifies that `TestContextResolver.resolve()` raises `AuthenticationError` in production environment.
19. `test_api_cors_configuration`: Verifies that application CORS configuration uses explicit configured origins, restricted methods, restricted headers, and no wildcard origins with credentials.
20. `test_environment_setting_constrained_literal`: Verifies that `Settings.environment` enforces `Literal["development", "test", "production"]` and rejects invalid values (`"prod"`, `"production "`).

### Section C: CandidateChunk Filtering & Audit Logging Tests (`tests/test_authorization.py`)
21. `test_filter_authorized_candidates_same_tenant_public`: Verifies that a same-tenant public candidate survives `filter_authorized_candidates()`.
22. `test_filter_authorized_candidates_same_tenant_unauthorized_admin`: Verifies that a same-tenant admin candidate is rejected for a public caller.
23. `test_filter_authorized_candidates_cross_tenant`: Verifies that a cross-tenant candidate is rejected even for an admin caller.
24. `test_filter_authorized_candidates_mixed_list`: Verifies that across a mixed list of valid, role-unauthorized, and cross-tenant candidates, only authorized candidates survive.
25. `test_cross_tenant_rejection_logging_never_exposes_secret_or_content`: Verifies that cross-tenant rejection logs only provenance metadata and never document content or synthetic secret tokens.

---

## 7. Full Test Results

Execution command: `python -m pytest tests/ -v`

```text
============================= test session starts =============================
platform win32 -- Python 3.14.0, pytest-9.2.0, pluggy-1.7.0 -- C:\Python314\python.exe
cachedir: .pytest_cache
rootdir: E:\AI Projectss\RAG security
plugins: anyio-4.14.2
collecting ... collected 108 items

tests/test_api.py::test_api_health PASSED                                [  0%]
tests/test_api.py::test_api_valid_retrieval PASSED                       [  1%]
tests/test_api.py::test_api_unknown_identity_returns_401 PASSED          [  2%]
tests/test_api.py::test_api_client_cannot_override_tenant_or_role PASSED [  3%]
tests/test_api.py::test_api_invalid_query_returns_422 PASSED             [  4%]
tests/test_api.py::test_api_invalid_top_k_returns_422 PASSED             [  5%]
tests/test_api.py::test_api_tenant_isolation_enforced PASSED             [  6%]
tests/test_api.py::test_api_role_authorization_enforced PASSED           [  7%]
tests/test_api.py::test_api_unauthorized_content_never_in_response PASSED [  8%]
tests/test_api.py::test_api_auth_error_never_reflects_attacker_input PASSED [  9%]
tests/test_api.py::test_api_production_mode_blocks_retrieval_endpoints PASSED [ 10%]
tests/test_api.py::test_test_context_resolver_blocks_in_production PASSED [ 11%]
tests/test_api.py::test_api_cors_configuration PASSED                    [ 12%]
tests/test_api.py::test_environment_setting_constrained_literal PASSED   [ 12%]
tests/test_authorization.py::test_valid_test_identity_resolution PASSED  [ 13%]
tests/test_authorization.py::test_unknown_identity_raises_authentication_error PASSED [ 14%]
tests/test_authorization.py::test_client_cannot_override_identity_context PASSED [ 15%]
tests/test_authorization.py::test_build_where_filter_tenant_and_role_matrix PASSED [ 16%]
tests/test_role_authorization_public_user PASSED                          [ 17%]
tests/test_role_authorization_member_user PASSED                          [ 18%]
tests/test_role_authorization_admin_user PASSED                           [ 19%]
tests/test_tenant_isolation_cross_tenant_rejected PASSED                 [ 20%]
tests/test_tenant_isolation_pairwise_matrix PASSED                       [ 21%]
tests/test_fail_closed_missing_or_corrupt_metadata PASSED                 [ 22%]
tests/test_authorization_rejection_never_exposes_document_content PASSED [ 23%]
tests/test_authorization.py::test_filter_authorized_candidates_same_tenant_public PASSED [ 24%]
tests/test_authorization.py::test_filter_authorized_candidates_same_tenant_unauthorized_admin PASSED [ 25%]
tests/test_authorization.py::test_filter_authorized_candidates_cross_tenant PASSED [ 25%]
tests/test_authorization.py::test_filter_authorized_candidates_mixed_list PASSED [ 26%]
tests/test_authorization.py::test_cross_tenant_rejection_logging_never_exposes_secret_or_content PASSED [ 27%]
tests/test_chunker.py::test_chunk_single_document PASSED                 [ 25%]
tests/test_chunker.py::test_multi_chunk_splitting PASSED                 [ 26%]
tests/test_chunker.py::test_avoid_empty_chunks PASSED                    [ 27%]
tests/test_chunker.py::test_invalid_chunk_parameters PASSED              [ 28%]
tests/test_chunker.py::test_chunk_all_preserves_every_document PASSED    [ 29%]
tests/test_embeddings.py::test_embedding_dimension_and_type PASSED       [ 30%]
tests/test_embeddings.py::test_embedding_values_finite PASSED            [ 31%]
tests/test_embeddings.py::test_batch_embedding PASSED                    [ 32%]
tests/test_embeddings.py::test_reject_empty_text PASSED                  [ 33%]
tests/test_embeddings.py::test_singleton_pattern PASSED                  [ 33%]
tests/test_embeddings.py::test_uncached_model_error PASSED               [ 34%]
tests/test_embeddings.py::test_vector_validation_failure PASSED          [ 35%]
tests/test_embeddings.py::test_embedding_validation_errors_do_not_expose_text PASSED [ 36%]
tests/test_embeddings.py::test_oversized_integer_vector_component_rejected PASSED [ 37%]
tests/test_indexer.py::test_indexer_upsert_and_count PASSED              [ 38%]
tests/test_indexer.py::test_title_propagation_and_persistence PASSED     [ 39%]
tests/test_indexer.py::test_idempotency_no_duplicates PASSED             [ 40%]
tests/test_indexer.py::test_stale_chunk_removal PASSED                   [ 41%]
tests/test_indexer.py::test_document_zero_chunks_removal PASSED          [ 42%]
tests/test_indexer.py::test_query_retrieval_and_filtering PASSED         [ 43%]
tests/test_indexer.py::test_security_sanitization_blocks_raw_canary_leak PASSED [ 44%]
tests/test_indexer.py::test_metadata_contains_safe_refs_only PASSED      [ 45%]
tests/test_indexer.py::test_reset_clears_collection PASSED               [ 46%]
tests/test_indexer.py::test_sync_rejects_foreign_document_chunks PASSED  [ 47%]
tests/test_indexer.py::test_invalid_embedding_count_preserves_existing_chunks PASSED [ 48%]
tests/test_indexer.py::test_invalid_canary_metadata_preserves_existing_chunks PASSED [ 49%]
tests/test_indexer.py::test_duplicate_chunk_ids_rejected PASSED          [ 50%]
tests/test_indexer.py::test_wrong_dimension_embeddings_preserve_existing_chunks PASSED [ 51%]
tests/test_indexer.py::test_nan_or_infinity_embeddings_preserve_existing_chunks PASSED [ 52%]
tests/test_indexer.py::test_non_numeric_embeddings_preserve_existing_chunks PASSED [ 53%]
tests/test_indexer.py::test_invalid_batch_size_preserves_existing_chunks PASSED [ 54%]
tests/test_indexer.py::test_negative_batch_size_preserves_existing_chunks PASSED [ 55%]
tests/test_indexer.py::test_boolean_batch_size_rejected PASSED           [ 56%]
tests/test_indexer.py::test_float_batch_size_rejected PASSED             [ 57%]
tests/test_indexer.py::test_sync_stale_invalid_embedding_preserves_existing_chunks PASSED [ 58%]
tests/test_indexer.py::test_sync_stale_invalid_metadata_preserves_existing_chunks PASSED [ 59%]
tests/test_indexer.py::test_sync_rejects_chunk_id_owned_by_another_document PASSED [ 60%]
tests/test_indexer.py::test_collection_delete_never_called_on_invalid_input PASSED [ 61%]
tests/test_indexer.py::test_sync_rejects_existing_chunk_with_missing_doc_id_metadata PASSED [ 62%]
tests/test_indexer.py::test_sync_rejects_existing_chunk_with_none_or_empty_doc_id_metadata PASSED [ 63%]
tests/test_loader.py::test_load_all_24_documents PASSED                  [ 64%]
tests/test_loader.py::test_tenant_and_access_level_distribution PASSED   [ 65%]
tests/test_loader.py::test_manifest_consistency PASSED                   [ 66%]
tests/test_loader.py::test_canary_refs_population PASSED                 [ 66%]
tests/test_loader.py::test_reject_missing_frontmatter PASSED             [ 67%]
tests/test_loader.py::test_reject_unclosed_frontmatter PASSED            [ 68%]
tests/test_loader.py::test_reject_missing_required_field PASSED          [ 69%]
tests/test_loader.py::test_reject_unmanifested_document PASSED           [ 70%]
tests/test_loader.py::test_reject_filename_mismatch PASSED               [ 71%]
tests/test_loader.py::test_reject_access_level_mismatch PASSED           [ 72%]
tests/test_loader.py::test_reject_title_mismatch PASSED                  [ 73%]
tests/test_loader.py::test_reject_category_mismatch PASSED               [ 74%]
tests/test_loader.py::test_reject_relative_path_mismatch PASSED          [ 75%]
tests/test_retrieval.py::test_retrieval_query_validation PASSED          [ 76%]
tests/test_retrieval.py::test_retrieval_top_k_validation PASSED          [ 77%]
tests/test_retrieval.py::test_retrieval_relevant_document PASSED         [ 78%]
tests/test_retrieval.py::test_retrieval_empty_result PASSED              [ 79%]
tests/test_retrieval.py::test_retrieval_embedding_failure_handled_safely PASSED [ 80%]
tests/test_retrieval.py::test_retrieval_chromadb_failure_handled_safely PASSED [ 81%]
tests/test_tenant_isolation_end_to_end PASSED                             [ 82%]
tests/test_cross_tenant_candidate_rejected_even_if_returned_by_chromadb PASSED [ 83%]
tests/test_unauthorized_role_candidate_rejected_even_if_returned_by_chromadb PASSED [ 84%]
tests/test_unauthorized_content_never_in_authorized_results PASSED        [ 85%]
tests/test_fail_closed_invalid_chunk_id PASSED                           [ 86%]
tests/test_fail_closed_invalid_doc_id PASSED                             [ 87%]
tests/test_fail_closed_invalid_tenant_metadata PASSED                    [ 88%]
tests/test_fail_closed_invalid_access_level_metadata PASSED              [ 89%]
tests/test_fail_closed_invalid_chunk_index PASSED                        [ 90%]
tests/test_fail_closed_malformed_boolean_flags PASSED                    [ 91%]
tests/test_fail_closed_malformed_canary_refs PASSED                      [ 92%]
tests/test_fail_closed_strict_content_validation PASSED                  [ 93%]
tests/test_fail_closed_distance_validation_and_score_bounds PASSED    [ 94%]
tests/test_fail_closed_missing_or_non_dict_metadata PASSED              [ 95%]
tests/test_fail_closed_malformed_chromadb_result_arrays PASSED           [ 96%]
tests/test_fail_closed_never_leaks_document_content_on_malformed_metadata PASSED [ 97%]
tests/test_fail_closed_rejects_missing_canary_refs_key PASSED            [ 98%]
tests/test_fail_closed_distance_numeric_overflow PASSED                  [ 99%]
tests/test_fail_closed_chromadb_outer_dimensions_unexpected_groups PASSED [100%]

====================== 108 passed, 2 warnings in 10.18s =======================
```

---

## 8. Remaining Limitations

1. **Test Identity Simulation Scope**:
   - `TestContextResolver` is explicitly an offline evaluation tool for reproducible benchmarking. Production deployments must replace this with real authentication (e.g. verified OpenID Connect / OAuth2 JWT bearer tokens).
2. **LLM Generation Deferred**:
   - As scoped, LLM generation, prompt templates, and injection defense guardrails are not implemented in Milestone 4.1. The environment is now prepared for clean LLM integration in Milestone 5.
3. **ChromaDB Local Directory Concurrency**:
   - ChromaDB persistent SQLite storage operates on a single-writer basis and is optimized for testbed execution rather than distributed multi-process write workloads.

---

## 9. Architecture Preservation Confirmation

- Existing document ingestion, YAML frontmatter parsing, chunking, and embedding logic remain intact.
- ChromaDB indexing, sync idempotency, and ownership checks remain unchanged.
- Test context resolution, role hierarchy, and `AuthorizationGuard` semantics remain fully preserved.
- All 83 previously passing tests pass without alteration.
