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
from app.authorization.evaluator import build_where_filter
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

        Both baseline and defended paths perform strictly equivalent common work:
        1. Query input validation (length and whitespace check)
        2. Query embedding via embed_text() (exactly 1 embedding operation per iteration)
        3. ChromaDB vector query with top_k=default_top_k
        4. Prompt preparation from retrieved chunks
        5. Output response processing

        Security-specific additions in the defended path:
        - ChromaDB metadata where_filter pre-filtering
        - Post-retrieval application AuthorizationGuard candidate verification
        - Trusted PromptBuilder XML-delimiter wrapping
        - OutputValidator exact canary substring scanning

        Standalone fake generation is measured separately and kept out of the pipeline latency overhead.
        """
        iterations = max(30, iterations)
        query_embedding_times: List[float] = []
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

        # -------------------------------------------------------------
        # Warm-up phase: 5 iterations strictly excluded from recorded samples
        # -------------------------------------------------------------
        for _ in range(5):
            warm_vec = self.pipeline.embedder.embed_text(query)
            _ = self.pipeline.indexer.query(query_embedding=warm_vec, top_k=settings.default_top_k)
            _ = self.pipeline.retriever.retrieve(query=query, context=context)

        # Precomputed vector and sample candidates for isolated stage micro-benchmarks
        precomputed_vector = self.pipeline.embedder.embed_text(query)
        sample_candidates = self.pipeline.retriever.retrieve(query=query, context=context)

        # -------------------------------------------------------------
        # Measurement phase: exactly `iterations` samples recorded
        # -------------------------------------------------------------
        for _ in range(iterations):
            # 1. Standalone Stage Micro-Benchmarks (Component Isolation)
            # Stage A: Query Embedding
            t0 = time.perf_counter()
            _ = self.pipeline.embedder.embed_text(query)
            t1 = time.perf_counter()
            query_embedding_times.append((t1 - t0) * 1000.0)

            # Stage B: Standalone raw retrieval (ChromaDB query without guard, using precomputed vector)
            t0 = time.perf_counter()
            self.pipeline.indexer.query(query_embedding=precomputed_vector, top_k=settings.default_top_k, where_filter=None)
            t1 = time.perf_counter()
            raw_retrieval_times.append((t1 - t0) * 1000.0)

            # Stage C: Standalone authorization guard (filtering candidate list)
            t0 = time.perf_counter()
            self.pipeline.guard.filter_authorized_candidates(candidates=sample_candidates, context=context)
            t1 = time.perf_counter()
            auth_guard_times.append((t1 - t0) * 1000.0)

            # Stage D: Standalone prompt construction
            t0 = time.perf_counter()
            bundle = self.pipeline.prompt_builder.build(query=query, chunks=sample_candidates)
            t1 = time.perf_counter()
            prompt_times.append((t1 - t0) * 1000.0)

            # Stage E: Standalone offline fake generation (kept separate from pipeline timing)
            t0 = time.perf_counter()
            raw_output = self.pipeline.fake_provider.generate(bundle.user_prompt)
            t1 = time.perf_counter()
            gen_offline_times.append((t1 - t0) * 1000.0)

            # Stage F: Standalone output validation
            t0 = time.perf_counter()
            self.pipeline.output_validator.validate(raw_output)
            t1 = time.perf_counter()
            val_times.append((t1 - t0) * 1000.0)

            # 2. Contiguous End-to-End Pipeline Timing (Equivalent Work)
            # Both paths perform:
            # - Input query validation
            # - Query embedding generation (embed_text called exactly once)
            # - Vector retrieval from ChromaDB
            # - Prompt formatting
            # - Response output handling

            # Defended Path:
            # Validate -> Embed query -> Query with pre-filter & AuthorizationGuard ->
            # Construct XML prompt -> Validate output with CanaryRegistry
            t0 = time.perf_counter()
            if len(query) > settings.max_query_length or not query.strip():
                raise ValueError("Query exceeds validation boundaries")
            defended_query_vec = self.pipeline.embedder.embed_text(query)
            where_filter = build_where_filter(context)
            filtered_cands = self.pipeline.indexer.query(
                query_embedding=defended_query_vec,
                top_k=settings.default_top_k,
                where_filter=where_filter,
            )
            authorized_cands = self.pipeline.guard.filter_authorized_candidates(
                candidates=filtered_cands,
                context=context,
            )
            p_bundle = self.pipeline.prompt_builder.build(query=query, chunks=authorized_cands)
            self.pipeline.output_validator.validate(sample_output)
            t1 = time.perf_counter()
            defended_totals.append((t1 - t0) * 1000.0)

            # Baseline Path (Equivalent work without security controls):
            # Validate -> Embed query -> Retrieve raw ChromaDB chunks (no pre-filter, no guard) ->
            # Plain text prompt formatting -> Direct output handling without validator
            t0 = time.perf_counter()
            if len(query) > settings.max_query_length or not query.strip():
                raise ValueError("Query exceeds validation boundaries")
            baseline_query_vec = self.pipeline.embedder.embed_text(query)
            raw_chunks = self.pipeline.indexer.query(
                query_embedding=baseline_query_vec,
                top_k=settings.default_top_k,
                where_filter=None,
            )
            _ = f"Question: {query}\nContext: {' '.join(c.content for c in raw_chunks)}"
            _ = len(sample_output) > 0
            t1 = time.perf_counter()
            baseline_totals.append((t1 - t0) * 1000.0)

        components = {
            "standalone_query_embedding": calculate_stats(query_embedding_times),
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
