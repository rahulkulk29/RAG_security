"""
Evaluation runner and orchestrator for Milestone 6.
"""
import os
import sys
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any

from app.core.config import settings
from evaluation.schemas import EvaluationCase, CaseExecutionResult, EvaluationSummary
from evaluation.dataset import load_evaluation_dataset
from evaluation.pipeline import EvaluationPipeline
from evaluation.metrics import compute_evaluation_summary
from evaluation.latency import LatencyBenchmarker
from evaluation.reporter import EvaluationReporter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluation")


class EvaluationRunner:
    """Executes the complete Milestone 6 Adversarial RAG Evaluation."""

    def __init__(
        self,
        output_dir: Optional[Path] = None,
        live: bool = False,
        benchmark_iterations: int = 30,
    ):
        self.output_dir = output_dir or (settings.project_root / "evaluation_results")
        self.live = live
        self.benchmark_iterations = max(30, benchmark_iterations)
        self.pipeline = EvaluationPipeline()
        self.reporter = EvaluationReporter(output_dir=self.output_dir)

    def run(self, verify_repeatability: bool = False) -> EvaluationSummary:
        """Runs the complete evaluation and exports artifacts."""
        mode = "live" if self.live else "offline"
        logger.info("Starting Milestone 6 Adversarial Evaluation (Mode: %s)", mode)

        # 1. Load evaluation dataset
        cases = load_evaluation_dataset()
        logger.info("Loaded %d test cases across all categories.", len(cases))

        # Check live client prerequisites if live mode requested
        live_client = None
        model_id = "deterministic-fake-provider"
        provider_type = "deterministic_fake_provider"

        if self.live:
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                logger.error("Live evaluation mode requested (--live), but GEMINI_API_KEY is not set.")
                raise ValueError(
                    "Live evaluation mode requested (--live), but GEMINI_API_KEY environment variable is not configured. "
                    "Cannot execute live evaluation without valid credentials. Terminating."
                )
            from app.generation.client import GeminiClient
            live_client = GeminiClient(model_id="gemini-1.5-flash")
            model_id = live_client.model_id
            provider_type = "google_genai"
            logger.info("Live Gemini generation enabled (Model: %s)", model_id)

        # 2. Execute all cases through the security pipeline
        results: List[CaseExecutionResult] = []
        for idx, case in enumerate(cases, 1):
            logger.debug("[%d/%d] Executing case %s: %s", idx, len(cases), case.case_id, case.name)
            res = self.pipeline.execute_case(case=case, mode=mode, live_client=live_client)
            results.append(res)

        # 3. Controlled security ablations (isolated harness)
        logger.info("Running controlled security ablations...")
        ablations = [
            self.pipeline.run_ablation_no_guard(cases),
            self.pipeline.run_ablation_no_prefilter(cases),
            self.pipeline.run_ablation_no_output_validator(cases),
        ]

        # 4. Latency micro-benchmarking (at least 30 iterations)
        logger.info("Running latency micro-benchmarks (%d iterations)...", self.benchmark_iterations)
        benchmarker = LatencyBenchmarker(pipeline=self.pipeline)
        latency_summary = benchmarker.benchmark_pipeline_stages(iterations=self.benchmark_iterations)

        # 5. Compute aggregate metrics
        timestamp = datetime.now(timezone.utc).isoformat()
        summary = compute_evaluation_summary(
            results=results,
            execution_mode=mode,
            model_id=model_id,
            provider_type=provider_type,
            timestamp=timestamp,
            ablations=ablations,
        )

        # 6. Export all artifacts
        logger.info("Exporting evaluation artifacts to %s...", self.output_dir)
        self.reporter.export_all(
            results=results,
            summary=summary,
            latency_summary=latency_summary,
        )

        # 7. Repeatability verification if requested
        if verify_repeatability and mode == "offline":
            logger.info("Verifying deterministic repeatability across passes...")
            pass2_results = [self.pipeline.execute_case(c, mode="offline") for c in cases]
            for r1, r2 in zip(results, pass2_results):
                assert r1.passed == r2.passed, f"Repeatability mismatch on case {r1.case_id}: pass1={r1.passed}, pass2={r2.passed}"
                assert r1.attack_succeeded == r2.attack_succeeded
                assert r1.blocked == r2.blocked
                assert r1.attack_outcome == r2.attack_outcome
            logger.info("Repeatability verified: 100% deterministic identical outputs across passes.")

        # Print summary table to console
        self._print_console_summary(summary, latency_summary)

        return summary

    def _print_console_summary(self, summary: EvaluationSummary, latency: Any):
        print("\n" + "=" * 80)
        print("MILESTONE 6: ADVERSARIAL RAG SECURITY EVALUATION SUMMARY")
        print("=" * 80)
        print(f"Execution Mode:             {summary.execution_mode}")
        print(f"Model ID:                   {summary.model_id} ({summary.provider_type})")
        print(f"Total Cases Evaluated:      {summary.total_cases} ({summary.attack_cases_count} attacks, {summary.benign_cases_count} benign)")
        
        overall_asr_str = f"{summary.overall_asr_percent:.2f}%" if summary.overall_asr_percent is not None else "Not Evaluated (Offline Mode)"
        eval_asr_str = f"{summary.evaluated_attack_categories_asr_percent:.2f}%" if summary.evaluated_attack_categories_asr_percent is not None else "N/A"
        false_block_str = f"{summary.benign_false_block_rate_percent:.2f}% ({summary.benign_queries_blocked}/{summary.benign_queries_executed})"
        canary_leak_str = (
            f"{summary.canary_metrics.canary_leakage_rate_percent:.2f}% ({summary.canary_metrics.canary_tokens_leaked_count}/{summary.canary_metrics.canary_emission_attempts})"
            if summary.canary_metrics.canary_leakage_rate_percent is not None
            else "N/A"
        )
        canary_intercept_str = (
            f"{summary.canary_metrics.canary_interception_rate_percent:.2f}% ({summary.canary_metrics.canary_tokens_detected_count}/{summary.canary_metrics.canary_emission_attempts})"
            if summary.canary_metrics.canary_interception_rate_percent is not None
            else "N/A"
        )
        raw_retrieval_str = (
            f"{summary.authorization_metrics.raw_unauthorized_retrieval_rate_percent:.2f}% ({summary.authorization_metrics.cases_with_raw_unauthorized_candidates}/{summary.authorization_metrics.total_authorization_cases})"
            if summary.authorization_metrics.raw_unauthorized_retrieval_rate_percent is not None
            else "N/A"
        )
        auth_accept_str = (
            f"{summary.authorization_metrics.unauthorized_acceptance_rate_percent:.2f}% ({summary.authorization_metrics.unauthorized_acceptance_cases_count}/{summary.authorization_metrics.total_authorization_cases})"
            if summary.authorization_metrics.unauthorized_acceptance_rate_percent is not None
            else "N/A"
        )

        print(f"Overall Attack Success Rate: {overall_asr_str}")
        print(f"Evaluated Controls ASR:     {eval_asr_str}")
        print(f"Raw Unauthorized Retrieval: {raw_retrieval_str}")
        print(f"Guard Acceptance Rate:      {auth_accept_str}")
        print(f"Canary Interception Rate:   {canary_intercept_str}")
        print(f"Canary Leakage Rate:        {canary_leak_str}")
        print(f"Benign False-Block Rate:    {false_block_str}")
        print(f"Human Review Status:        {summary.human_review_status}")
        print(f"Security Latency Overhead:  {latency.overhead_ms:.2f} ms ({latency.overhead_percent:.2f}%)")
        print(f"Infrastructure Errors:      {summary.infrastructure_errors_count}")
        print("-" * 80)
        print(f"{'Category':<32} | {'Total':<5} | {'Eligible':<8} | {'ASR (%)':<15} | {'Status':<12}")
        print("-" * 80)
        for m in summary.category_metrics:
            asr_display = f"{m.asr_percent:.2f}%" if m.asr_percent is not None else "Not Evaluated"
            print(f"{m.category:<32} | {m.total_cases:<5} | {m.eligible_cases:<8} | {asr_display:<15} | {m.evaluation_status:<12}")
        print("=" * 80 + "\n")
