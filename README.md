# RAG Security Testing and Prompt Injection Defense

An enterprise-grade, defense-in-depth security architecture and adversarial evaluation harness for Retrieval-Augmented Generation (RAG) systems.

## Overview

This project implements and evaluates comprehensive security controls designed to prevent:
1. **Cross-Tenant Data Leakage**: Enforcing strict tenant isolation across storage and application layers.
2. **Role-Based Privilege Escalation**: Guarding document access tiers (`public`, `member`, `admin`) within tenants.
3. **Prompt Injection & Delimiter Breakout**: Encapsulating untrusted retrieved context and user inputs within strict XML delimiters.
4. **Synthetic Secret & Canary Exfiltration**: Scanning and blocking canary token leakage at the output boundary using `OutputValidator` and `CanaryRegistry`.
5. **Malformed & Smuggled Inputs**: Fail-closed schema validation and server-side identity resolution.

---

## Architecture & Security Boundaries

```
[ User Request ] ───> [ Input Validation ] ───> [ Server-Side Identity Resolution ]
                             │
                             ▼
              [ Boundary 1: ChromaDB Vector Query (with pre-filter) ]
                             │
                             ▼
              [ Boundary 2: Application AuthorizationGuard ]
                             │
                             ▼
              [ Boundary 3: Trusted PromptBuilder (XML Delimiters) ]
                             │
                             ▼
              [ Generation: Gemini / Deterministic Provider ]
                             │
                             ▼
              [ Boundary 4: OutputValidator (Canary Substring Interception) ]
                             │
                             ▼
                       [ Sanitized Response ]
```

---

## Evaluation Modes

### 1. Offline Deterministic Mode (Default)
Offline evaluation tests the deterministic architectural boundaries:
- Real sentence-transformer embeddings (`all-MiniLM-L6-v2`)
- Real ChromaDB vector retrieval
- Real application-level `AuthorizationGuard`
- Real `PromptBuilder` structural delimiters
- Real `OutputValidator` exact canary substring scanning
- Deterministic mock generation provider

> [!NOTE]
> Offline mode **does not claim to evaluate semantic LLM resistance** to prompt injection or secret extraction. The Attack Success Rate (ASR) for semantic categories (`direct_prompt_injection`, `indirect_prompt_injection`, `delimiter_breakout`, and `synthetic_secret_extraction`) is reported as **`Not Evaluated` (`null`)**. Structural prompt integrity is measured separately.

```bash
# Run offline evaluation with dual-pass repeatability verification
python run_evaluation.py --repeatability --output-dir evaluation_results
```

### 2. Live Gemini Evaluation Mode (`--live`)
Live mode sends assembled prompts to the Gemini API (`gemini-1.5-flash`) via the `google-genai` SDK to evaluate real LLM semantic compliance and injection resistance.

> [!IMPORTANT]
> Live evaluation requires an explicit `--live` flag and a valid `GEMINI_API_KEY` environment variable. If credentials are missing, the runner terminates immediately with a non-zero exit code (it **never** silently falls back to offline mode).

```bash
# Set credentials
export GEMINI_API_KEY="your-api-key"   # Linux/macOS
$env:GEMINI_API_KEY="your-api-key"     # PowerShell

# Run live evaluation
python run_evaluation.py --live --output-dir evaluation_results
```

---

## Quickstart & Reproduction

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Dependencies installed via `pip install -r requirements.txt` (or FastAPI, Pydantic, ChromaDB, Sentence-Transformers, pytest)

### 1. Run Unit & Regression Tests
```bash
# Run evaluation-focused test suite
python -m pytest tests/test_evaluation.py -v

# Run full project test suite (296 tests across Milestones 1-6)
python -m pytest tests/ -v
```

### 2. Run Adversarial Evaluation Benchmark
```bash
python run_evaluation.py --repeatability --output-dir evaluation_results
```

### 3. Generated Evaluation Artifacts
Evaluation results are exported to `evaluation_results/`:
1. `summary.json`: High-level scorecard and metrics across all boundaries.
2. `results.json`: Full per-case execution telemetry.
3. `results.csv`: Flattened tabular case telemetry.
4. `category_metrics.csv`: Aggregate statistics per attack category.
5. `latency_metrics.json`: Contiguous baseline vs defended micro-benchmarks.
6. `human_review_template.csv`: Blank adjudication template for manual analysis.
7. `evaluation_report.md`: Executive markdown evaluation scorecard.

---

## Known Scope & Limitations
1. **Offline Mode Scope**: Offline evaluation demonstrates structural and architectural defense effectiveness, not live LLM semantic compliance.
2. **Canary Matching**: `OutputValidator` scans for exact substring matches of registered canary tokens. It does not perform semantic or encoded (e.g. Base64) paraphrase detection.
3. **Synthetic Corpus**: Vector retrieval benchmarks use a controlled synthetic corpus of 24 multi-tenant chunks. Real-world vector databases with millions of vectors may exhibit different clustering density.

