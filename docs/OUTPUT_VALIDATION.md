# Milestone 5.4 — Output Validation and Synthetic Secret Protection

## Overview

Milestone 5.4 introduces an output security boundary that inspects generated answers before they can be returned to API callers. This layer validates the structure and length of the generated response and scans for unauthorized synthetic secret leakage.

---

## 1. Where Output Validation Occurs

Output validation is enforced inside `GenerationService.answer()` in `app/generation/service.py` immediately following LLM generation and strictly prior to constructing `GenerationResult`:

```
1. Resolve identity (TestContextResolver)
2. Retrieve candidates (SecureRetriever)
3. Authorize candidates (AuthorizationGuard)
4. Build trusted prompt bundle (PromptBuilder)
5. Generate answer (GeminiClient)
6. Validate output & scan for synthetic secrets (OutputValidator)  <-- [Milestone 5.4]
7. Extract safe source metadata & return GenerationResult
```

Validation occurs within the service layer so that all callers (HTTP endpoints, batch evaluation harnesses, test runners) consistently receive the same security guarantees.

---

## 2. Canary Registry Integration

The synthetic secret registry (`CanaryRegistry`) reads exclusively from the server-side file configured at `settings.canaries_path` (`data/secrets/canaries.json`).

- **No client input**: Canary tokens are never accepted from API requests, query parameters, or HTTP headers.
- **Fail-closed semantics**: If `canaries.json` is missing, unreadable, or contains malformed JSON/records, `CanaryRegistry` raises `SecretRegistryError`. The generation pipeline immediately aborts and returns HTTP 500 without generating or returning an answer.
- **Empty registry rejection by default**: An empty registry is rejected by default (`allow_empty=False`), raising `SecretRegistryError` with a static sanitized message to prevent unmonitored generation.
- **Production, staging, and development fail-closed enforcement**: In production, staging, and development environments (`settings.environment != "test"`), `CanaryRegistry` strictly rejects zero-token registries under all circumstances, even if `allow_empty=True` is passed. `GenerationService` and `OutputValidator` fail closed during construction if the registry is empty.
- **Explicit test-only empty registry**: Passing `allow_empty=True` is honored strictly when `settings.environment == "test"` for isolated unit tests that explicitly test non-leakage behaviors.
- **In-memory immutability**: Tokens are parsed into an immutable `frozenset[str]` at initialization and cached in memory.

---

## 3. What the Validator Rejects

`OutputValidator.validate()` enforces four deterministic checks:

1. **Non-string output**: Non-string values raise `OutputValidationError`.
2. **Empty or whitespace-only output**: Empty strings or strings containing only whitespace characters raise `OutputValidationError`.
3. **Over-limit output**: Output exceeding `settings.max_answer_length` (default 50,000 characters) raises `OutputValidationError`. Output is never silently truncated.
4. **Synthetic secret leakage**: Output containing any registered synthetic canary token raises `SensitiveOutputDetectedError`.

Safe outputs undergo conservative normalization: leading and trailing whitespace is stripped (`answer.strip()`), while all internal whitespace, newlines, markdown formatting, and punctuation remain untouched.

---

## 4. Detection Policy and Known Limitations

### Detection Policy
- **Iterative substring scanning**: The scanner iterates sequentially over the set of registered canary tokens and checks substring containment (`token in text`) against the generated answer text. The scan complexity is proportional to $O(T \times L)$, where $T$ is the number of registered tokens and $L$ is the length of the generated answer.
- **Case-sensitive matching**: Synthetic tokens in the corpus adhere to standardized conventions (all-caps identifiers such as `CANARY_TENANT_A_MEMBER_APITOKEN_55210` and `FLAG{...}`). Case-sensitive matching minimizes false positives while matching the exact token syntax.

### Known Limitations
- **No semantic or paraphrase detection**: Exact substring matching cannot detect secrets that the LLM has paraphrased, summarized, or described conceptually.
- **No encoding or transformation detection**: Encoded variants (Base64, hex, rot13, URL-encoded), transliterated text, or spaced/spaced-out characters (e.g. `C A N A R Y`) are not caught by exact substring matching.
- **Scope**: This defense is a targeted synthetic secret leakage control for evaluation and benchmark scoring in the security testbed. It is not an enterprise Data Loss Prevention (DLP) system or multi-modal exfiltration guardrail.

---

## 5. Safe Failure and Error Mapping

When an error occurs, the system fails safely without leaking sensitive information:

| Failure Mode | Raised Exception | HTTP Code | API Response Detail |
|---|---|---|---|
| Query / parameter validation error | `ValueError`, `PromptConstructionError`, `ContextLengthExceededError` | 422 Unprocessable Content | `Invalid generation request parameters` |
| Malformed / empty / oversized answer | `OutputValidationError` | 502 Bad Gateway | `Generation provider temporarily unavailable` |
| Canary token detected in answer | `SensitiveOutputDetectedError` | 502 Bad Gateway | `Generation provider temporarily unavailable` |
| Registry file missing, malformed, or empty | `SecretRegistryError` | 500 Internal Server Error | `Generation service temporarily unavailable` |
| Unexpected validation failure | Generic `Exception` | 500 Internal Server Error | `Internal server error` |

**Information Leakage Guarantees:**
- Canary tokens, candidate secrets, internal file paths, exception messages, and raw generated answers are **never** included in exception messages, HTTP response bodies, or application logs.
- Log records record only static error descriptions and the exception class name (`type(exc).__name__`).
