"""
Performance and Latency Benchmarking for Security Controls.
Measures timing overhead across each pipeline stage and controlled security ablations.
"""
import time
import statistics
from typing import List, Dict, Any, Optional

from app.core.config import settings
from app.core.types import TenantId, AccessLevel
from app.core.schemas import UserContext
from evaluation.schemas import LatencyStats, LatencySummary


def calculate_stats(measurements: List[float]) -> LatencyStats:
    """Calculates mean, median, P95, min, and max for a series of millisecond latencies."""
    if not measurements:
        return LatencyStats(count=0, mean_ms=0.0, median_ms=0.0, p95_ms=0.0, min_ms=0.0, max_ms=0.0)

    sorted_m = sorted(measurements)
    n = len(sorted_m)
    p95_idx = int(0.95 * n)
    p95_val = sorted_m[min(p95_idx, n - 1)]

    return LatencyStats(
        count=n,
        mean_ms=round(statistics.mean(measurements), 3),
        median_ms=round(statistics.median(measurements), 3),
        p95_ms=round(p95_val, 3),
        min_ms=round(min(measurements), 3),
        max_ms=round(max(measurements), 3),
    )


class LatencyBenchmarker:
    """Micro-benchmarks individual stages and end-to-end paths of the secure RAG pipeline."""

    def __init__(self, pipeline: Any):
        self.pipeline = pipeline

    def benchmark_pipeline_stages(self, iterations: int = 30) -> LatencySummary:
        """
        Runs repeated timing loops across each pipeline stage using monotonic time.perf_counter().
        Measures comparable end-to-end baseline (unguarded) vs defended paths without double-counting.
        Both paths perform equivalent work: query validation, query embedding, vector search,
        prompt construction, and response handling.
        """
        iterations = max(30, iterations)
        raw_retrieval_times: List[float] = []
        auth_guard_times: List[float] = []
        prompt_times: List[float] = []
        gen_offline_times: List[float] = []
        val_times: List[float] = []
        defended_totals: List[float] = []
        baseline_totals: List[float] = []

        context = UserContext(
            user_id="user_ta_member",
            tenant_id=TenantId.TENANT_A,
            role=AccessLevel.MEMBER,
        )
        query = "What are the core capabilities and API features offered by the ApexPay platform?"
        sample_output = "The ApexPay platform provides enterprise payment routing and settlement APIs."

        # Pre-warm query embedding and ChromaDB collection before timed iterations
        for _ in range(5):
            warm_vec = self.pipeline.embedder.embed_text(query)
            _ = self.pipeline.indexer.query(query_embedding=warm_vec, top_k=settings.default_top_k)
            _ = self.pipeline.retriever.retrieve(query=query, context=context)

        # Pre-calculated vector for isolated component micro-benchmarks
        query_vector = self.pipeline.embedder.embed_text(query)
        sample_candidates = self.pipeline.retriever.retrieve(query=query, context=context)

        for _ in range(iterations):
            # ---------------------------------------------------------
            # 1. Standalone Stage Micro-Benchmarks (Component Isolation)
            # ---------------------------------------------------------
            # Standalone raw retrieval (ChromaDB query without guard, using precomputed vector)
            t0 = time.perf_counter()
            self.pipeline.indexer.query(query_embedding=query_vector, top_k=settings.default_top_k, where_filter=None)
            t1 = time.perf_counter()
            raw_retrieval_times.append((t1 - t0) * 1000.0)

            # Standalone authorization guard (filtering candidate list)
            t0 = time.perf_counter()
            self.pipeline.guard.filter_authorized_candidates(candidates=sample_candidates, context=context)
            t1 = time.perf_counter()
            auth_guard_times.append((t1 - t0) * 1000.0)

            # Standalone prompt construction
            t0 = time.perf_counter()
            bundle = self.pipeline.prompt_builder.build(query=query, chunks=sample_candidates)
            t1 = time.perf_counter()
            prompt_times.append((t1 - t0) * 1000.0)

            # Standalone offline fake generation (kept separate from pipeline timing)
            t0 = time.perf_counter()
            raw_output = self.pipeline.fake_provider.generate(bundle.user_prompt)
            t1 = time.perf_counter()
            gen_offline_times.append((t1 - t0) * 1000.0)

            # Standalone output validation
            t0 = time.perf_counter()
            self.pipeline.output_validator.validate(raw_output)
            t1 = time.perf_counter()
            val_times.append((t1 - t0) * 1000.0)

            # ---------------------------------------------------------
            # 2. Contiguous End-to-End Pipeline Timing (Equivalent Work)
            # ---------------------------------------------------------
            # Both paths perform:
            # - Input query validation
            # - Query embedding generation
            # - Vector retrieval from ChromaDB
            # - Prompt formatting
            # - Response output handling

            # Defended Path:
            # Validates query -> Embeds query -> Retrieves with pre-filter & AuthorizationGuard ->
            # Constructs secure XML prompt -> Validates output with CanaryRegistry
            t0 = time.perf_counter()
            if len(query) > settings.max_query_length or not query.strip():
                raise ValueError("Query exceeds validation boundaries")
            cands = self.pipeline.retriever.retrieve(query=query, context=context, top_k=settings.default_top_k)
            p_bundle = self.pipeline.prompt_builder.build(query=query, chunks=cands)
            self.pipeline.output_validator.validate(sample_output)
            t1 = time.perf_counter()
            defended_totals.append((t1 - t0) * 1000.0)

            # Baseline Path (Equivalent work without security controls):
            # Validates query -> Embeds query -> Retrieves raw ChromaDB chunks (no pre-filter, no guard) ->
            # Formats plain prompt without XML boundaries -> Delivers output without validator
            t0 = time.perf_counter()
            if len(query) > settings.max_query_length or not query.strip():
                raise ValueError("Query exceeds validation boundaries")
            base_vec = self.pipeline.embedder.embed_text(query)
            raw_chunks = self.pipeline.indexer.query(query_embedding=base_vec, top_k=settings.default_top_k, where_filter=None)
            _ = f"Question: {query}\nContext: {' '.join(c.content for c in raw_chunks)}"
            _ = sample_output
            t1 = time.perf_counter()
            baseline_totals.append((t1 - t0) * 1000.0)

        components = {
            "standalone_raw_retrieval": calculate_stats(raw_retrieval_times),
            "standalone_authorization_guard": calculate_stats(auth_guard_times),
            "standalone_prompt_construction": calculate_stats(prompt_times),
            "standalone_offline_fake_generation": calculate_stats(gen_offline_times),
            "standalone_output_validation": calculate_stats(val_times),
            "total_defended_pipeline": calculate_stats(defended_totals),
            "total_baseline_pipeline": calculate_stats(baseline_totals),
        }

        defended_mean = components["total_defended_pipeline"].mean_ms
        baseline_mean = components["total_baseline_pipeline"].mean_ms
        overhead_ms = round(defended_mean - baseline_mean, 3)
        overhead_percent = round((overhead_ms / baseline_mean) * 100.0, 2) if baseline_mean > 0 else 0.0

        return LatencySummary(
            mode="offline_deterministic",
            sample_count=iterations,
            components=components,
            defended_total_mean_ms=defended_mean,
            baseline_total_mean_ms=baseline_mean,
            overhead_ms=overhead_ms,
            overhead_percent=overhead_percent,
        )
