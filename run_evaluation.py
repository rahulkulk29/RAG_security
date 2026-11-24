#!/usr/bin/env python3
"""
CLI entrypoint to execute the Milestone 6 Adversarial RAG Security Evaluation.

Usage:
    # Run standard offline deterministic evaluation:
    python run_evaluation.py

    # Verify repeatability across multiple passes:
    python run_evaluation.py --repeatability

    # Run with live Gemini evaluation (requires GEMINI_API_KEY):
    python run_evaluation.py --live

    # Custom output directory:
    python run_evaluation.py --output-dir custom_eval_results
"""
import sys
import argparse
from pathlib import Path

# Add project root to sys.path
WORKSPACE = Path(__file__).resolve().parent
if str(WORKSPACE) not in sys.path:
    sys.path.insert(0, str(WORKSPACE))

from evaluation.runner import EvaluationRunner


def main():
    parser = argparse.ArgumentParser(
        description="Milestone 6: Complete Adversarial RAG Security Evaluation Runner"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=WORKSPACE / "evaluation_results",
        help="Directory to write evaluation artifacts (results.json, summary.json, reports, etc.)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        default=False,
        help="Opt-in to live Gemini API evaluation (requires GEMINI_API_KEY environment variable)",
    )
    parser.add_argument(
        "--repeatability",
        action="store_true",
        default=False,
        help="Execute two consecutive offline passes to verify deterministic repeatability",
    )
    parser.add_argument(
        "--benchmark-iterations",
        type=int,
        default=30,
        help="Number of timing iterations for latency micro-benchmarking (default: 30)",
    )

    args = parser.parse_args()

    runner = EvaluationRunner(
        output_dir=args.output_dir,
        live=args.live,
        benchmark_iterations=args.benchmark_iterations,
    )

    try:
        summary = runner.run(verify_repeatability=args.repeatability)
        print(f"Artifacts successfully exported to: {args.output_dir.resolve()}")
        sys.exit(0)
    except Exception as exc:
        print(f"\n[FATAL] Evaluation runner failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

