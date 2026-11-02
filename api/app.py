"""
LLM Security Gateway — FastAPI Application

Three functional endpoints + health:
  POST /detect         — User prompt injection scan
  POST /scan-context   — RAG chunk indirect injection scan
  POST /safe-inference — Full pipeline (detect → model stub → filter)
  GET  /health         — Operational health with fail-closed status

HTTP status code decisions:
  422 for content policy rejections (not 403 — see DECISIONS.md ADR-004)
  503 for detector unhealthy
  500 for internal errors

Structured logging: every request logs request_id, source, latency, result.
Audit trail is not optional — security controls without audit logs are unauditable.
"""

import logging
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from detector import (
    FilterError,
    OutputFilter,
    PromptInjectionDetector,
    Severity,
)

# ---- Structured logging ----
logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "msg": %(message)s}',
)
logger = logging.getLogger("llm-gateway")

app = FastAPI(
    title="LLM Security Gateway",
    description=(
        "Multi-layer prompt injection detection and output filtering for Vertex AI endpoints. "
        "Layer 2 (custom detector) and Layer 3 (output filter) of the inference security pipeline."
    ),
    version="1.0.0",
)

detector = PromptInjectionDetector()
output_filter = OutputFilter()


# ---- Request / Response Models ----

class DetectRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=50_000)
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class DetectResponse(BaseModel):
    request_id: str
    is_malicious: bool
    severity: str
    category: str | None
    matched_pattern: str | None
    confidence: float
    latency_ms: float
    details: str


class ContextScanRequest(BaseModel):
    chunks: list[str] = Field(..., min_length=1, max_length=100)
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class ContextScanResponse(BaseModel):
    request_id: str
    total_chunks: int
    malicious_chunks: int
    safe_chunk_indices: list[int]
    details: list[dict]
    total_latency_ms: float


class InferenceRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=50_000)
    rag_chunks: list[str] = Field(default_factory=list)
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class InferenceResponse(BaseModel):
    request_id: str
    response: str
    detection_latency_ms: float
    filter_latency_ms: float
    redacted_types: list[str]
    system_leak_detected: bool


# ---- Endpoints ----

@app.post("/detect", response_model=DetectResponse)
async def detect_injection(request: DetectRequest):
    """
    Scan a user prompt for injection patterns.

    Returns 422 if malicious (content policy violation, not auth failure).
    Returns 503 if detector is unhealthy (fail-closed — do not route around this).
    """
    result = detector.analyze(request.prompt, source="user_input")

    log_payload = {
        "request_id": request.request_id,
        "endpoint": "/detect",
        "is_malicious": result.is_malicious,
        "severity": result.severity.value,
        "category": result.category.value if result.category else None,
        "matched_pattern": result.matched_pattern,
        "latency_ms": result.latency_ms,
        "input_length": result.input_length,
    }

    if result.matched_pattern == "detector_unhealthy":
        logger.error(f'"event": "detector_unhealthy", "detail": {log_payload}')
        raise HTTPException(status_code=503, detail="Detector unhealthy. Fail-closed.")

    if result.is_malicious:
        logger.warning(f'"event": "injection_detected", "detail": {log_payload}')
        raise HTTPException(
            status_code=422,
            detail={
                "error": "content_policy_violation",
                "severity": result.severity.value,
                "category": result.category.value if result.category else None,
                "request_id": request.request_id,
            },
        )

    logger.info(f'"event": "prompt_clean", "detail": {log_payload}')
    return DetectResponse(
        request_id=request.request_id,
        is_malicious=result.is_malicious,
        severity=result.severity.value,
        category=result.category.value if result.category else None,
        matched_pattern=result.matched_pattern,
        confidence=result.confidence,
        latency_ms=result.latency_ms,
        details=result.details,
    )


@app.post("/scan-context", response_model=ContextScanResponse)
async def scan_rag_context(request: ContextScanRequest):
    """
    Scan RAG-retrieved chunks for indirect injection before prompt assembly.

    Integration: call this AFTER vector_db.search(), BEFORE template.format().
    Malicious chunks are identified — caller must exclude them from context.
    Request continues with reduced context; partial answer beats poisoned answer.

    Does NOT block the request — returns which chunks are safe/malicious.
    Caller decides whether to proceed with reduced context or abort.
    """
    results = detector.analyze_context(request.chunks)

    safe_indices = [i for i, r in enumerate(results) if not r.is_malicious]
    malicious_details = [
        {
            "chunk_index": i,
            "severity": r.severity.value,
            "category": r.category.value if r.category else None,
            "pattern": r.matched_pattern,
            "latency_ms": r.latency_ms,
        }
        for i, r in enumerate(results)
        if r.is_malicious
    ]

    total_latency = sum(r.latency_ms for r in results)

    logger.info(
        f'"event": "rag_context_scan", "request_id": "{request.request_id}", '
        f'"total_chunks": {len(request.chunks)}, '
        f'"malicious_chunks": {len(malicious_details)}, '
        f'"total_latency_ms": {total_latency:.3f}'
    )

    if malicious_details:
        logger.warning(
            f'"event": "indirect_injection_detected", "request_id": "{request.request_id}", '
            f'"malicious_chunks": {malicious_details}'
        )

    return ContextScanResponse(
        request_id=request.request_id,
        total_chunks=len(request.chunks),
        malicious_chunks=len(malicious_details),
        safe_chunk_indices=safe_indices,
        details=malicious_details,
        total_latency_ms=total_latency,
    )


@app.post("/safe-inference", response_model=InferenceResponse)
async def safe_inference(request: InferenceRequest):
    """
    Full pipeline: detect → (RAG scan) → model → filter.

    Order of operations:
    1. Scan user prompt — block on injection
    2. Scan RAG chunks — drop malicious chunks, proceed with safe subset
    3. Stub model inference (replace with actual Vertex AI call in production)
    4. Filter model response — redact PII, flag system leaks

    In production: replace _stub_model_call() with Vertex AI SDK call.
    The filter and detection logic remain unchanged regardless of model provider.
    """
    # Step 1: User prompt scan
    prompt_result = detector.analyze(request.prompt, source="user_input")
    if prompt_result.is_malicious:
        logger.warning(
            f'"event": "injection_blocked_at_inference", '
            f'"request_id": "{request.request_id}", '
            f'"pattern": "{prompt_result.matched_pattern}"'
        )
        raise HTTPException(
            status_code=422,
            detail={
                "error": "content_policy_violation",
                "stage": "input_detection",
                "request_id": request.request_id,
            },
        )

    # Step 2: RAG context scan
    safe_chunks = request.rag_chunks
    if request.rag_chunks:
        chunk_results = detector.analyze_context(request.rag_chunks)
        safe_chunks = [
            c for c, r in zip(request.rag_chunks, chunk_results) if not r.is_malicious
        ]
        dropped = len(request.rag_chunks) - len(safe_chunks)
        if dropped > 0:
            logger.warning(
                f'"event": "rag_chunks_dropped", '
                f'"request_id": "{request.request_id}", '
                f'"dropped": {dropped}, "retained": {len(safe_chunks)}'
            )

    # Step 3: Model inference (stub — replace with Vertex AI call)
    raw_response = _stub_model_call(request.prompt, safe_chunks)

    # Step 4: Output filter
    try:
        filter_result = output_filter.filter(raw_response)
    except FilterError as exc:
        logger.error(
            f'"event": "output_filter_failed", "request_id": "{request.request_id}", '
            f'"error": "{exc}"'
        )
        raise HTTPException(status_code=500, detail="Output filter failure. Response blocked.")

    if filter_result.has_system_leak:
        logger.warning(
            f'"event": "system_leak_detected", '
            f'"request_id": "{request.request_id}", '
            f'"leak_types": {filter_result.system_leaks_detected}'
        )

    return InferenceResponse(
        request_id=request.request_id,
        response=filter_result.filtered,
        detection_latency_ms=prompt_result.latency_ms,
        filter_latency_ms=filter_result.latency_ms,
        redacted_types=filter_result.redacted_types,
        system_leak_detected=filter_result.has_system_leak,
    )


@app.get("/health")
async def health_check():
    """
    Health check for orchestrator / load balancer.

    Returns fail_mode: "closed" explicitly — orchestrator must treat
    detector health failure as a hard dependency, not soft degradation.
    Do NOT configure load balancer to route around an unhealthy detector
    to Model Armor alone — that's fail-open by another path.

    Runs a known-benign probe through the detector to verify pipeline
    is functional (not just that the process is alive).
    """
    probe_result = detector.analyze("What is the capital of France?", source="health_probe")

    return {
        "status": "healthy" if detector._healthy else "unhealthy",
        "fail_mode": "closed",
        "detector_pattern_count": len(detector._patterns),
        "probe_latency_ms": round(probe_result.latency_ms, 3),
        "probe_result": "clean" if not probe_result.is_malicious else "ERROR_PROBE_TRIGGERED",
    }


def _stub_model_call(prompt: str, context_chunks: list[str]) -> str:
    """
    Stub model call — replace with actual Vertex AI SDK invocation.

    Production replacement:
        from google.cloud import aiplatform
        endpoint = aiplatform.Endpoint(endpoint_name)
        response = endpoint.predict(instances=[{"prompt": assembled_prompt}])
        return response.predictions[0]
    """
    context = "\n".join(context_chunks) if context_chunks else "No context provided."
    return (
        f"[STUB RESPONSE] Prompt received ({len(prompt)} chars). "
        f"Context chunks used: {len(context_chunks)}. "
        "Replace this with actual Vertex AI endpoint call."
    )
