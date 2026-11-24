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
    structural_containment_passed: bool = True  # Backward compatibility alias
    error: Optional[str] = None
    error_type: Optional[str] = None
    http_status: Optional[int] = None
    raw_candidates_count: int = 0
    raw_authorized_candidates_count: int = 0
    raw_unauthorized_candidates_count: int = 0
    authorized_candidates_count: int = 0
    unauthorized_guard_accepted_count: int = 0
    unauthorized_prompt_exposure_count: int = 0
    unauthorized_response_exposure_count: int = 0
    has_raw_unauthorized_candidates: bool = False
    unauthorized_doc_in_candidates: bool = False
    unauthorized_doc_in_prompt: bool = False
    unauthorized_doc_in_response: bool = False
    canary_in_retrieved_context: bool = False
    canary_in_prompt: bool = False
    canary_in_raw_model_output: bool = False
    canary_detected_by_validator: bool = False
    canary_in_final_response: bool = False
    canary_in_response: bool = False  # Backward compatibility alias
    structural_containment_failed: bool = False
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
    asr_percent: Optional[float] = None  # None/null when not evaluated or eligible_cases == 0
    prompt_structure_integrity_rate_percent: Optional[float] = None
    structural_containment_rate_percent: Optional[float] = None  # Backward compatibility alias
    unauthorized_access_count: int = 0
    canary_leakage_count: int = 0
    evaluation_status: str = "evaluated"  # "evaluated" | "not_evaluated"


class AuthorizationMetrics(BaseModel):
    """Detailed authorization metrics across multiple architectural boundaries."""
    total_authorization_cases: int
    cases_with_raw_unauthorized_candidates: int
    raw_unauthorized_retrieval_rate_percent: Optional[float] = None
    unauthorized_acceptance_cases_count: int
    unauthorized_acceptance_rate_percent: Optional[float] = None
    unauthorized_prompt_exposure_cases_count: int
    unauthorized_prompt_exposure_rate_percent: Optional[float] = None
    unauthorized_response_exposure_cases_count: int
    unauthorized_response_exposure_rate_percent: Optional[float] = None
    # Backward compatibility aliases
    raw_unauthorized_retrieval_count: int = 0
    unauthorized_acceptance_count: int = 0
    unauthorized_prompt_exposure_count: int = 0
    unauthorized_response_exposure_count: int = 0


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
    num_executions: int = 0
    baseline_config: str = ""
    defended_config: str = ""
    metric_name: str = ""
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
