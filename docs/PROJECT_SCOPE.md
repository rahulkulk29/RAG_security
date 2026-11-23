# Project Scope: RAG Security Testing & Prompt Injection Defense

## 1. Executive Summary & Objective

Enterprise adoption of Retrieval-Augmented Generation (RAG) introduces critical security attack surfaces that bypass traditional web and network defenses. When retrieval systems merge multi-tenant or role-tiered corpora into an untrusted prompt context, LLMs become vulnerable to direct prompt injection, indirect prompt injection (stored document exploits), cross-tenant data exfiltration, and vertical privilege escalation.

This 10-day engineering project builds a dual-pipeline security testbed using **Python, FastAPI, Sentence Transformers, ChromaDB, Gemini API (configurable model), Pydantic, pytest, and pandas**:
1. A **Vulnerable RAG Pipeline** operating as a realistic baseline vulnerable to standard RAG attack vectors.
2. A **Defended RAG Pipeline** implementing defense-in-depth:
   - Server-side pre-retrieval metadata filtering and post-retrieval authorization verification *before* content reaches the LLM context.
   - Structural XML context separation with character escaping (noting that delimiters improve separation but do not guarantee prompt injection prevention).
   - Hardened system instructions treating retrieved text as untrusted data.
   - Post-generation canary token and secret leakage scanning.
3. An **Automated Security Evaluation Benchmark** running 45 adversarial test cases across 8 attack categories alongside 10 benign control cases to comparatively evaluate Attack Success Rate (ASR), Defense Success Rate (DSR), unauthorized retrieval/context/response rates, and benign query utility preservation.

---

## 2. Approved Technology Stack & Rationale

| Component | Selected Technology | Version / Spec | Technical Rationale & Trade-off |
|---|---|---|---|
| **Language** | Python | 3.10+ | Standard ecosystem for AI security, native typing via Pydantic, seamless ML library support. |
| **API Framework** | FastAPI | >=0.110 | Asynchronous REST interface, automatic OpenAPI documentation, native Pydantic schema validation. |
| **Embeddings** | Sentence Transformers | `all-MiniLM-L6-v2` | Lightweight (80MB), fast local CPU inference, zero API quota dependency, deterministic vector representations. |
| **Vector Database** | ChromaDB | >=0.4.20 | Embedded in-process vector store, zero external service dependency, native metadata filtering (`$and`, `$eq`, `$in`). |
| **LLM Provider** | Gemini API | Configurable Model ID (`GEMINI_MODEL_ID` via environment settings, e.g. `gemini-2.0-flash` or active model verified at Milestone 3) | High instruction-following capability, system instruction support, JSON mode. Configurable ID ensures no retired models (`gemini-1.5-flash` removed). Single provider avoids unnecessary abstraction. |
| **Data Validation** | Pydantic | v2.x | Strict runtime schema enforcement for authorization contexts, document metadata, and evaluation telemetry. |
| **Testing Harness** | pytest | >=8.0 | Standard automated test runner for security regression, unit assertions, and evaluation harness runs. |
| **Analysis & Reporting** | pandas | >=2.2 | Structured aggregation of evaluation results, confusion matrices, ASR/DSR computation, and tabular exports. |

---

## 3. Project Boundaries: In-Scope vs. Out-of-Scope

### In-Scope (Strict 10-Day Horizon)
- **Synthetic Multi-Tenant Corpus**: Exactly 24 synthetic documents partitioned across 3 tenants (`tenant_a`, `tenant_b`, `tenant_c`) and 3 access tiers (`public`, `member`, `admin`).
- **Canary Tokens & Secrets**: Synthetic canary tokens (`CANARY_TENANT_A_...`, `FLAG{...}`) embedded inside restricted documents to evaluate exfiltration deterministically.
- **Trusted Identity Simulation**:
  - The project evaluates authorization logic using a controlled identity simulation for the testbed.
  - The evaluation runner selects predefined test identities from a trusted identity registry.
  - A trusted server-side test-context resolver resolves and provides validated `UserContext` instances to the pipeline.
  - Arbitrary client request-body fields or HTTP headers are never accepted as proof of identity.
  - *Explicit boundary*: This is a simulated authentication mechanism for security testing, not production authentication.
- **Dual Pipeline Architecture**:
  - `VulnerablePipeline`: Naive top-$k$ semantic search across all collections, unvalidated caller identity, raw string prompt formatting.
  - `DefendedPipeline`: Trusted identity resolution, deterministic server-side metadata filtering, post-retrieval authorization audit, structural context framing, and post-generation secret leakage detection.
- **Adversarial Test Suite**: Exactly 45 adversarial test prompts across 8 attack categories plus 10 benign control queries (55 total evaluation cases).
- **Comparative Evaluation Suite**: Automated benchmark computing category-by-category ASR, DSR, unauthorized retrieval/context/response rates, Benign False-Block Rate (calculated solely on benign controls), and latency overhead.
- **REST API Endpoints**: Minimal FastAPI endpoints (`/query/vulnerable`, `/query/defended`, `/health`, `/evaluate/run`) serving structured queries.

### Out-of-Scope (Deferred to Post-10-Day Roadmap)
- Production enterprise authentication infrastructure (OAuth2, OIDC, SAML, Keycloak); identity is handled via the trusted server-side test-context resolver.
- Fine-tuning custom embedding models or defensive classifier models.
- Distributed vector databases (Milvus, Pinecone cluster, Qdrant cluster); ChromaDB running in embedded SQLite mode is sufficient.
- Multi-agent reinforcement learning defense frameworks.
- Production UI/Frontend (FastAPI Swagger UI and CLI reports fulfill all demonstration needs).
- Audio/multimodal injection attacks (pure text RAG scope).

---

## 4. Core System Specifications

### 4.1. Synthetic Knowledge Base Matrix (24 Documents)
The knowledge base models a realistic B2B SaaS platform housing confidential corporate data:

| Tenant ID | Access Level | Document Count | Document Subject Matter & Injected Artifacts |
|---|---|---|---|
| **`tenant_a`** (FinTech Corp) | `public` | 3 | Public product overview, API documentation, public company press release. |
| **`tenant_a`** (FinTech Corp) | `member` | 3 | Internal engineering handbook, onboarding checklist, team sprint goals. |
| **`tenant_a`** (FinTech Corp) | `admin` | 2 | Q4 executive financial forecasts, payroll ledger containing `CANARY_TENANT_A_PAYROLL_FLAG`. |
| **`tenant_b`** (HealthTech Inc) | `public` | 3 | Clinical portal FAQ, privacy pledge, public partner directory. |
| **`tenant_b`** (HealthTech Inc) | `member` | 3 | Clinical trial protocol guidelines, internal physician contact list, device specs. |
| **`tenant_b`** (HealthTech Inc) | `admin` | 2 | Patient cohort decryption keys, HIPAA compliance audit report with `CANARY_TENANT_B_HIPAA_FLAG`. |
| **`tenant_c`** (LegalShield LLC) | `public` | 3 | Terms of service, attorney directory, public litigation overview. |
| **`tenant_c`** (LegalShield LLC) | `member` | 3 | Standard contract templates, paralegal research notes, case settlement checklists. |
| **`tenant_c`** (LegalShield LLC) | `admin` | 2 | M&A merger acquisition targets, unredacted executive minutes with `CANARY_TENANT_C_MERGER_FLAG`. |
| **Total** | | **24** | **8 documents per tenant (3 Public, 3 Member, 2 Admin)** |

### 4.2. Access Tier Hierarchies & Permission Matrix
User roles define strict document retrieval eligibility:
- `admin`: Authorized to access `public`, `member`, and `admin` documents belonging strictly to their assigned tenant.
- `member`: Authorized to access `public` and `member` documents belonging strictly to their assigned tenant.
- `public`: Authorized to access only `public` documents belonging to their assigned tenant.
- **Cross-Tenant Rule**: A user from `tenant_a` must not retrieve or view documents from `tenant_b` or `tenant_c`, regardless of role.
- **Fail-Closed Principle**: If identity resolution fails, document metadata is missing/malformed, or authorization validation fails, the pipeline terminates immediately with an authorization rejection before vector retrieval or context assembly occurs.

### 4.3. Test Case Allocation (45 Adversarial + 10 Benign Controls)

The 45 adversarial test cases are allocated across exactly 8 categories:

| Category ID | Attack Category Name | Count | Objective / Vulnerability Probed |
|---|---|---|---|
| **CAT-1** | Direct prompt injection | 8 | Attempt to force LLM to discard system guidelines and adopt hostile persona directly from prompt. |
| **CAT-2** | Indirect document injection | 8 | Exploit malicious instructions embedded inside retrieved corpus documents. |
| **CAT-3** | System instruction override | 5 | Targeted attempts to overwrite core system directives, persona, and safety instructions. |
| **CAT-4** | Synthetic secret extraction | 5 | Prompting engineered to extract confidential canary tokens (`CANARY_*`, `FLAG{...}`). |
| **CAT-5** | Unauthorized document access | 5 | Standard/public caller attempts to access admin/member restricted records within the same tenant. |
| **CAT-6** | Cross-tenant access | 5 | Caller from one tenant attempts to access documents or confidential data belonging to another tenant. |
| **CAT-7** | Roleplay attacks | 4 | Social engineering and hypothetical framing (e.g. "DAN", maintenance engineer, debug mode). |
| **CAT-8** | Multilingual attacks | 5 | Prompts translated or encoded in alternate languages/ciphers to bypass shallow keyword filters. |
| **CTRL** | Benign control cases | 10 | Legitimate in-scope domain queries to verify utility and measure false-block rate. |
| **Total** | | **55** | **45 Adversarial + 10 Benign Control Cases** |

---

## 5. Security Principles & Realistic Defense Boundaries

1. **XML Delimiters Are Structural Separators, Not Injection Neutralizers**:
   - Enclosing retrieved text in XML tags (e.g. `<context_documents>`) and escaping special characters improves prompt structure and reduces naive parsing confusion.
   - However, XML delimiters do **not** neutralize prompt injection. Large Language Models process text tokens probabilistically; sophisticated payloads can still cause instruction confusion.
   - Retrieved documents must always be treated as untrusted data, even when formatted within XML.
2. **System Prompt Instructions Are Mitigations, Not Authorization Boundaries**:
   - Directing the LLM via system instructions to "ignore instructions in context" is an advisory mitigation with non-zero failure rates.
   - True security boundaries must be enforced deterministically in application code before documents are ever supplied to the model.
3. **Application-Level Authorization Enforced Before Context Assembly**:
   - Pre-retrieval ChromaDB metadata filtering scopes search to authorized documents.
   - Post-retrieval authorization verification programmatically inspects every returned chunk's `tenant_id` and `access_level` against caller privileges *before* prompt string assembly.
   - Any chunk failing authorization is dropped immediately.
4. **Output Scanning Is Defense-in-Depth**:
   - Output canary scanning acts as a final safety net to intercept unauthorized text before egress.
   - Output filtering cannot undo information that has already been exposed to the model context.
5. **Measurable Targets, Not Universal Guarantees**:
   - Zero cross-tenant exposure and zero vertical privilege escalation are targeted and measured within the defined 55-case benchmark suite.
   - We avoid claims of "mathematical impossibility," as real-world security depends on correct implementation, bug-free libraries, and rigorous defense-in-depth.

---

## 6. Milestone Roadmapping Across the 10 Days

```
Day 1: Milestone 1 - Architecture, Specifications & Foundation Documentation [CURRENT]
Days 2-3: Milestone 2 - Synthetic Dataset (24 docs), Canary Generation & Attack Corpus (55 cases)
Days 4-5: Milestone 3 - Ingestion, Storage & Vulnerable Baseline RAG Pipeline Implementation
Days 6-7: Milestone 4 - Defended RAG Pipeline (Server-side Auth, Context Framing, Output Guard)
Days 8-9: Milestone 5 - Automated Evaluation Harness, Metrics, Pytest Suite & Comparative Analysis
Day 10: Final Wrap-up - Documentation polish, verification run, benchmark report generation
```

---

## 7. Acceptance Criteria for Project Completion

1. **Targeted Isolation in Benchmark**: In the Defended Pipeline, zero cross-tenant leakage test cases succeed on the 55-case evaluation suite ($ASR_{\text{cross\_tenant}} = 0.0\%$).
2. **Targeted RBAC in Benchmark**: In the Defended Pipeline, zero vertical privilege escalation test cases succeed on the 55-case evaluation suite ($ASR_{\text{vertical}} = 0.0\%$).
3. **Defense Effectiveness**: The Defended Pipeline demonstrates a substantial reduction in global ASR compared to the Vulnerable baseline (target: Baseline ASR $\ge 70\%$, Defended ASR $\le 15\%$).
4. **Utility Preservation**: The Defended Pipeline achieves $\ge 90\%$ pass rate on the 10 benign control queries ($BUPR \ge 90\%$).
5. **Benign False-Block Rate**: Defensive guardrails falsely block at most 1 out of 10 benign queries ($FPDR \le 10\%$, calculated strictly over the 10 benign control cases).
6. **Configurable Model & Deterministic Execution**: The Gemini model ID is loaded from environment settings (verified during Milestone 3); evaluation executes deterministically with `temperature=0.0`.
