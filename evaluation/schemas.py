"""
Pydantic schemas and dataclasses for Milestone 6 Security Evaluation.
"""
from typing import Optional, Any, Literal, List, Dict
from pydantic import BaseModel, Field


class EvaluationCase(BaseModel):
    """Single test or attack case definition."""
    case_id: str
    name: str
    category: str
    description: str
    prompt: str
    test_identity_id: str
    target_tenant: Optional[str] = None
    target_access_level: Optional[str] = None
    target_doc_id: Optional[str] = None
    canary_token: Optional[str] = None
    forbidden_substrings: list[str] = Field(default_factory=list)
    expected_response_pattern: str = ""
    security_property: str = ""
    success_criteria: str = ""
    expected_security_outcome: str = ""
    expected_blocked: bool = True
    expected_leakage: bool = False
    rationale: str = ""
    evaluation_method: str = ""


class CaseExecutionResult(BaseModel):
    """Detailed execution telemetry for a single evaluated case."""
    case_id: str
    name: str
    category: str
    test_identity_id: str
    prompt: str
    execution_mode: str  # "offline" | "live"
    passed: bool  # True if security guarantee held
    attack_succeeded: bool  # True if attacker succeeded in unauthorized action
    blocked: bool  # True if request was blocked/intercepted
    attack_outcome: Literal[
        "successful_attack",
        "defended",
        "inconclusive",
        "infrastructure_error",
        "not_evaluated",
    ]
    semantic_asr_evaluated: bool = False  # False for semantic prompt injections & offline secret extractions
    prompt_structure_integrity_passed: bool = True
    error: Optional[str] = None
    error_type: Optional[str] = None
    http_status: Optional[int] = None

    # Raw ChromaDB inspection telemetry
    raw_inspection_status: Literal["completed", "failed", "inconclusive"] = "completed"
    raw_inspection_error: Optional[str] = None
    raw_candidates_count: int = 0
    raw_authorized_candidates_count: int = 0
    raw_unauthorized_candidates_count: int = 0
    has_raw_unauthorized_candidates: bool = False

    # Guard and downstream boundary telemetry
    guard_inspection_status: Literal["completed", "failed", "inconclusive"] = "completed"
    guard_presented_candidates_count: int = 0
    guard_presented_unauthorized_candidates_count: int = 0
    authorized_candidates_count: int = 0
    unauthorized_guard_accepted_count: int = 0
    unauthorized_doc_in_candidates: bool = False
    prompt_candidates_count: int = 0
    unauthorized_prompt_exposure_count: int = 0
    unauthorized_doc_in_prompt: bool = False
    unauthorized_response_exposure_count: int = 0
    unauthorized_doc_in_response: bool = False

    # Canary detection & emission telemetry
    canary_in_retrieved_context: bool = False
    canary_in_prompt: bool = False
    canary_in_raw_model_output: bool = False
    canary_detected_by_validator: bool = False
    canary_in_final_response: bool = False

    sanitized_excerpt: Optional[str] = None
    latency_ms: dict[str, float] = Field(default_factory=dict)
    human_review_needed: bool = False
    human_review_decision: Optional[str] = None  # Blank initially
    human_review_rationale: Optional[str] = None  # Blank initially
    reviewer_id: Optional[str] = None  # Blank initially
    review_timestamp: Optional[str] = None  # Blank initially


class CategoryMetric(BaseModel):
    """Aggregate metrics for a single attack category or benign control."""
    category: str
    total_cases: int
    eligible_cases: int
    attack_success_count: int
    attack_defended_count: int
    inconclusive_count: int = 0
    infrastructure_error_count: int = 0
    not_evaluated_count: int = 0
    asr_percent: Optional[float] = None  # None/null when not evaluated, benign, or eligible_cases == 0
    prompt_structure_integrity_rate_percent: Optional[float] = None
    unauthorized_access_count: int = 0
    canary_leakage_count: int = 0
    evaluation_status: str = "evaluated"  # "evaluated" | "not_evaluated" | "not_applicable"


class AuthorizationMetrics(BaseModel):
    """Detailed authorization metrics across multiple architectural boundaries."""
    total_authorization_cases: int

    # Boundary 1: Raw retrieval (ChromaDB unfiltered similarity query)
    eligible_raw_inspection_cases: int
    cases_with_raw_unauthorized_candidates: int
    raw_unauthorized_retrieval_case_rate_percent: Optional[float] = None
    total_raw_candidates: int
    total_raw_unauthorized_candidates: int
    raw_unauthorized_candidate_rate_percent: Optional[float] = None

    # Boundary 2: AuthorizationGuard verification
    eligible_authorization_cases: int
    eligible_guard_inspection_cases: int = 0
    unauthorized_guard_acceptance_cases_count: int
    unauthorized_guard_acceptance_case_rate_percent: Optional[float] = None
    total_candidates_presented_to_guard: int = 0
    total_unauthorized_candidates_presented_to_guard: int
    total_unauthorized_candidates_accepted_by_guard: int
    unauthorized_guard_acceptance_candidate_rate_percent: Optional[float] = None

    # Boundary 3: Prompt assembly
    unauthorized_prompt_exposure_cases_count: int
    unauthorized_prompt_exposure_case_rate_percent: Optional[float] = None
    total_candidates_in_prompt: int = 0
    total_unauthorized_candidates_in_prompt: int
    unauthorized_prompt_exposure_candidate_rate_percent: Optional[float] = None

    # Boundary 4: Final response delivery (case-level exposure + observed count; no candidate-level rate without response provenance)
    unauthorized_response_exposure_cases_count: int
    unauthorized_response_exposure_case_rate_percent: Optional[float] = None
    total_unauthorized_candidates_in_response: int


class CanaryLeakageMetrics(BaseModel):
    """Rigorous canary leakage metrics restricted to exercised emission attempts."""
    canary_in_retrieved_context_count: int = 0
    canary_in_prompt_count: int = 0
    canary_emission_attempts: int
    canary_tokens_detected_count: int
    canary_tokens_leaked_count: int
    canary_interception_rate_percent: Optional[float] = None
    canary_leakage_rate_percent: Optional[float] = None
    cases_not_exercising_canary_leakage: int
    infrastructure_errors: int = 0


class AblationComparison(BaseModel):
    """Controlled security ablation record with complete audit metadata."""
    name: str
    description: str
    cases_selected: List[str] = Field(default_factory=list)
    total_cases: int = 0
    executed_cases: int = 0
    failed_cases: int = 0
    inconclusive_cases: int = 0
    eligible_cases: int = 0
    baseline_config: str = ""
    defended_config: str = ""
    metric_name: str = ""
    baseline_events_count: int = 0
    defended_events_count: int = 0
    baseline_value: float = 0.0
    defended_value: float = 0.0
    observed_outcomes: str = ""
    limitations: str = ""


class LatencyStats(BaseModel):
    """Statistical summary for a latency measurement series."""
    count: int
    mean_ms: float
    median_ms: float
    p95_ms: float
    min_ms: float
    max_ms: float


class LatencySummary(BaseModel):
    """Latency overhead breakdown across pipeline stages."""
    mode: str
    sample_count: int
    components: Dict[str, LatencyStats]
    defended_total_mean_ms: float
    baseline_total_mean_ms: float
    overhead_ms: float
    overhead_percent: float


class EvaluationSummary(BaseModel):
    """High-level executive evaluation summary."""
    execution_mode: str  # "offline" | "live"
    timestamp: str
    model_id: str
    provider_type: str
    total_cases: int
    attack_cases_count: int
    benign_cases_count: int
    overall_asr_percent: Optional[float] = None  # None in offline mode because semantic attacks are not evaluated
    evaluated_attack_categories_asr_percent: Optional[float] = None  # ASR for deterministically testable controls
    benign_false_block_rate_percent: Optional[float] = None
    benign_queries_executed: int = 0
    benign_queries_blocked: int = 0
    canary_metrics: CanaryLeakageMetrics
    authorization_metrics: AuthorizationMetrics
    safe_failures_count: int
    infrastructure_errors_count: int
    human_review_status: str = "not_completed"
    category_metrics: List[CategoryMetric]
    ablations: List[AblationComparison] = Field(default_factory=list)
