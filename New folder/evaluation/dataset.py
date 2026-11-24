"""
Evaluation dataset loader and validator.
"""
import json
import logging
from pathlib import Path
from typing import Optional, List

from app.core.config import settings
from app.authorization.identity import TEST_IDENTITY_REGISTRY
from evaluation.schemas import EvaluationCase

logger = logging.getLogger(__name__)

CANONICAL_ATTACK_CATEGORIES = {
    "direct_prompt_injection",
    "indirect_prompt_injection",
    "cross_tenant_access",
    "role_authorization_bypass",
    "synthetic_secret_extraction",
    "delimiter_breakout",
    "malformed_oversized_input",
    "output_manipulation",
}

ALL_VALID_CATEGORIES = CANONICAL_ATTACK_CATEGORIES | {"benign_control"}


def load_evaluation_dataset(
    attacks_path: Optional[Path] = None,
    benign_path: Optional[Path] = None,
) -> List[EvaluationCase]:
    """
    Loads, parses, and validates the complete evaluation dataset.
    Combines adversarial attacks and benign control cases into a typed list.
    """
    if attacks_path is None:
        attacks_path = settings.data_dir / "attacks" / "test_cases.json"
    if benign_path is None:
        benign_path = settings.data_dir / "benign" / "benign_cases.json"

    if not attacks_path.exists():
        raise FileNotFoundError(f"Attack cases file not found: {attacks_path}")
    if not benign_path.exists():
        raise FileNotFoundError(f"Benign cases file not found: {benign_path}")

    with open(attacks_path, "r", encoding="utf-8") as f:
        attacks_raw = json.load(f)
    with open(benign_path, "r", encoding="utf-8") as f:
        benign_raw = json.load(f)

    if not isinstance(attacks_raw, list) or not isinstance(benign_raw, list):
        raise ValueError("Evaluation dataset files must contain a JSON array of test cases.")

    combined_raw = attacks_raw + benign_raw
    cases: List[EvaluationCase] = []
    seen_case_ids = set()

    for item in combined_raw:
        case = EvaluationCase.model_validate(item)
        if case.case_id in seen_case_ids:
            raise ValueError(f"Duplicate case_id found in evaluation dataset: {case.case_id}")
        seen_case_ids.add(case.case_id)

        if case.category not in ALL_VALID_CATEGORIES:
            raise ValueError(
                f"Unknown category '{case.category}' in case {case.case_id}. "
                f"Must be one of {sorted(ALL_VALID_CATEGORIES)}"
            )

        # Validate test_identity_id (allow explicit synthetic spoofing test)
        if case.test_identity_id != "user_nonexistent_identity" and case.test_identity_id not in TEST_IDENTITY_REGISTRY:
            raise ValueError(
                f"Unrecognized test_identity_id '{case.test_identity_id}' in case {case.case_id}"
            )

        cases.append(case)

    logger.info(
        "Successfully loaded %d evaluation cases (%d attacks, %d benign).",
        len(cases),
        len(attacks_raw),
        len(benign_raw),
    )
    return cases

