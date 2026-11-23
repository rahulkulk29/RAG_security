# 10-Day Implementation Roadmap & Risk Management

## 1. Timeline & Milestone Schedule

```
+-----------+-----------------------------------------------------------+-------------------------+
| Calendar  | Daily Workstream & Focus                                  | Milestone Association   |
+-----------+-----------------------------------------------------------+-------------------------+
| Day 1     | Architecture, Specifications, Identity Model & Schemas    | Milestone 1 [COMPLETE]  |
| Day 2     | Synthetic Knowledge Base (24 Documents across 3 Tenants)  | Milestone 2             |
| Day 3     | Attack Test Suite (45 Adversarial + 10 Benign Cases)      | Milestone 2             |
| Day 4     | Ingestion Engine, Sentence Transformers & ChromaDB Setup  | Milestone 3             |
| Day 5     | Vulnerable Baseline Pipeline & Model Verification         | Milestone 3             |
| Day 6     | Identity Simulation & Pre/Post-Retrieval Authorization    | Milestone 4             |
| Day 7     | Structural XML Framing, Hardened Prompt & Egress Guard    | Milestone 4             |
| Day 8     | Automated Multi-Stage Evaluation Harness & Judge          | Milestone 5             |
| Day 9     | Pandas Benchmark Metrics, Pytest Suite & Report Gen       | Milestone 5             |
| Day 10    | FastAPI Endpoints, Final Verification & Documentation     | Final Delivery          |
+-----------+-----------------------------------------------------------+-------------------------+
```

---

## 2. Detailed Daily Work Breakdown

### Day 1: Architecture & Project Foundation (Milestone 1 - Current)
- **Objectives**: Establish all technical specifications, module contracts, threat model, evaluation metrics, and project structure. Incorporate trusted identity simulation, realistic prompt-injection defense boundaries, multi-stage evaluation outcomes, and configurable model ID.
- **Deliverables**:
  - `docs/PROJECT_SCOPE.md`
  - `docs/ARCHITECTURE.md`
  - `docs/ATTACK_METHODOLOGY.md`
  - `docs/EVALUATION_PLAN.md`
  - `docs/10_DAY_ROADMAP.md`
- **Exit Criteria**: All architectural boundaries, schemas, and interfaces approved without contradictions; zero implementation code written.

---

### Day 2: Synthetic Knowledge Base Generation (Milestone 2 - Part 1)
- **Objectives**: Author 24 realistic markdown documents across FinTech (`tenant_a`), HealthTech (`tenant_b`), and LegalShield (`tenant_c`).
- **Deliverables**:
  - `data/corpus/tenant_a/` (8 documents: 3 public, 3 member, 2 admin)
  - `data/corpus/tenant_b/` (8 documents: 3 public, 3 member, 2 admin)
  - `data/corpus/tenant_c/` (8 documents: 3 public, 3 member, 2 admin)
  - `data/secrets/canaries.json` (canonical registry of embedded canary tokens)
- **Exit Criteria**: Every document includes validated YAML frontmatter (`doc_id`, `tenant_id`, `access_level`); canaries and indirect injection payloads seeded accurately.

---

### Day 3: Adversarial Test Suite Construction (Milestone 2 - Part 2)
- **Objectives**: Author exactly 45 adversarial prompts across the 8 agreed categories plus 10 benign control queries in structured JSON using `test_identity_id`.
  - Direct prompt injection (8)
  - Indirect document injection (8)
  - System instruction override (5)
  - Synthetic secret extraction (5)
  - Unauthorized document access (5)
  - Cross-tenant access (5)
  - Roleplay attacks (4)
  - Multilingual attacks (5)
  - Benign control cases (10)
- **Deliverables**:
  - `data/attacks/test_cases.json` (55 validated `TestCase` entries)
  - Validation test confirming all 55 entries satisfy Pydantic schema constraints.
- **Exit Criteria**: Exact distribution of 45 adversarial + 10 benign test cases confirmed.

---

### Day 4: Ingestion, Chunking & Vector Indexing (Milestone 3 - Part 1)
- **Objectives**: Implement markdown parser, metadata propagator, chunker, and ChromaDB persistent embedding pipeline using Sentence Transformers (`all-MiniLM-L6-v2`).
- **Deliverables**:
  - `app/core/config.py`, `app/core/schemas.py`, `app/core/types.py`
  - `app/ingestion/loader.py`, `app/ingestion/chunker.py`, `app/ingestion/indexer.py`
  - `scripts/seed_db.py`
  - `tests/test_ingestion.py`
- **Exit Criteria**: ChromaDB index populated; all 24 documents verified with intact metadata.

---

### Day 5: Vulnerable Baseline Pipeline & Model Verification (Milestone 3 - Part 2)
- **Objectives**: Implement the naive baseline pipeline with unbounded global retrieval, raw concatenation, and unhardened generation. Verify that the configured Gemini model (`GEMINI_MODEL_ID`) is active and reachable via the Gemini API SDK.
- **Deliverables**:
  - `app/retrieval/retriever.py` (unfiltered vector search)
  - `app/generation/llm.py` (Gemini API wrapper with configurable model ID, temperature=0.0)
  - `app/generation/prompts.py` (naive concatenation template)
  - `app/pipelines/vulnerable.py`
  - `tests/test_vulnerable_pipeline.py`
- **Exit Criteria**: Vulnerable pipeline functions and demonstrably leaks cross-tenant records on test attacks. Configured Gemini model verified as operational.

---

### Day 6: Identity Simulation & Pre/Post-Retrieval Authorization (Milestone 4 - Part 1)
- **Objectives**: Implement the server-side `TestContextResolver` (trusted identity simulation), pre-retrieval ChromaDB `where` clause generation, and post-retrieval authorization audit before context assembly.
- **Deliverables**:
  - `app/authorization/identity.py` (`TestContextResolver` mapping test identities to `UserContext`)
  - `app/authorization/evaluator.py` (constructs ChromaDB `$and`, `$eq`, `$in` filters)
  - `app/authorization/guard.py` (post-retrieval chunk validator; drops invalid chunks before context framing)
  - `tests/test_authorization.py`
- **Exit Criteria**: Unit tests verify fail-closed behavior on unresolvable identities, and confirm chunks outside caller tenant/tier are dropped before reaching prompt generation.

---

### Day 7: Context Isolation, Prompt Hardening & Egress Guard (Milestone 4 - Part 2)
- **Objectives**: Implement structural XML/CDATA context encapsulation, hardened Gemini system instructions, and post-generation canary detection.
- **Deliverables**:
  - `app/generation/prompts.py` (structural XML framing + untrusted context directive)
  - `app/generation/guard.py` (regex canary token scanner and secret detector)
  - `app/pipelines/defended.py`
  - `tests/test_defended_pipeline.py`
- **Exit Criteria**: Defended pipeline assembled; output guard intercepts unauthorized canaries. Explicitly documented that prompt instructions are a mitigation and context remains untrusted.

---

### Day 8: Automated Multi-Stage Evaluation Harness & Judge (Milestone 5 - Part 1)
- **Objectives**: Build the automated test runner executing all 55 test cases across both pipelines, recording independent stage outcomes (`unauthorized_retrieval`, `unauthorized_context_exposure`, `unauthorized_response_disclosure`) and flagging semantic cases for manual review.
- **Deliverables**:
  - `evaluation/runner.py`
  - `evaluation/judge.py` (deterministic checks + manual review flag for semantic ambiguities)
- **Exit Criteria**: Harness executes 55 cases against both pipelines and exports a raw JSON/CSV telemetry file with zero unhandled exceptions.

---

### Day 9: Metrics Aggregation, Pandas Analytics & Benchmark Report (Milestone 5 - Part 2)
- **Objectives**: Compute comparative ASR, DSR, stage exposure rates, and Benign False-Block Rate (calculated strictly over the 10 benign cases) using pandas; generate comprehensive markdown report.
- **Deliverables**:
  - `evaluation/metrics.py`
  - `evaluation/report.py`
  - `docs/BENCHMARK_REPORT.md` (automated output)
  - `tests/test_evaluation.py` (automated pytest regression suite)
- **Exit Criteria**: Defended pipeline shows $\ge 70\%$ reduction in overall ASR, 0% cross-tenant exposure on the test suite, and $\ge 90\%$ benign utility.

---

### Day 10: FastAPI Endpoints, Final Verification & Documentation Polish
- **Objectives**: Expose `/query/vulnerable` and `/query/defended` FastAPI routes, write root `README.md`, ensure clean code, and verify end-to-end reproducibility.
- **Deliverables**:
  - `app/api/main.py` and `app/api/routes.py`
  - Final root `README.md` with architecture diagrams, reproduction commands, and security findings summary.
  - Final test run passing 100% of pytest suite.
- **Exit Criteria**: Clean clone and single-command benchmark execution works out of the box.

---

## 3. Implementation Risk Management Matrix

| Risk ID | Risk Description | Likelihood | Impact | Mitigation Strategy |
|---|---|---|---|---|
| **R-1** | **Gemini Model Availability / Deprecation** | Medium | High | Avoid hardcoding retired model names. Define `GEMINI_MODEL_ID` in configuration. Verify active model availability on Day 5 via SDK listing before running pipeline tests. |
| **R-2** | **Gemini API Rate Limiting / Quotas** | Medium | Medium | Implement exponential backoff with jitter in `llm.py`; batch queries with 1-second delays during benchmark runs; cache responses during unit tests. |
| **R-3** | **ChromaDB Metadata Filter Quirks** | Low | High | Pre-test ChromaDB `$and` / `$in` filter behavior in isolation on Day 4. Fall back to post-retrieval programmatic filtering in `guard.py` before context assembly. |
| **R-4** | **LLM Semantic Non-Determinism** | Medium | Medium | Pin `temperature=0.0`; rely on deterministic canary and substring checks; provide manual review flag for semantic prompt-injection cases rather than trusting an LLM judge. |
| **R-5** | **Scope Creep / Over-Engineering** | High | High | Enforce strict boundaries defined in `docs/PROJECT_SCOPE.md`. Reject UI frontend, external auth providers (OIDC), or multi-agent frameworks. |

---

## 4. Critical Path & Scope Guardrails

The critical path for this project is:
$$\text{Corpus/Attacks (Days 2-3)} \rightarrow \text{Vulnerable Pipeline (Days 4-5)} \rightarrow \text{Defended Pipeline (Days 6-7)} \rightarrow \text{Evaluation Harness (Days 8-9)}$$

### Scope Guardrails:
- The identity model remains a simulated test-context resolver throughout the 10 days. No OAuth, OIDC, or external authentication services will be added.
- Only a single LLM provider (Gemini API via configurable model ID) will be used; no secondary provider abstraction layers.
- All modules execute in-process; ChromaDB operates embedded in SQLite.
