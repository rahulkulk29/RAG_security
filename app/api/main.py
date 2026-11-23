"""
FastAPI application entrypoint for RAG Security Testbed.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.routes import router as retrieval_router


def create_app() -> FastAPI:
    """Factory function creating configured FastAPI application."""
    app = FastAPI(
        title="RAG Security Testing & Prompt Injection Defense Testbed",
        description="Multi-tenant secure semantic retrieval, authorization gate, and benchmark API.",
        version="1.0.0",
    )

    # Secure CORS configuration: Explicit origins, methods, and headers
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=settings.cors_allowed_methods,
        allow_headers=settings.cors_allowed_headers,
    )

    app.include_router(retrieval_router)

    @app.get("/health", tags=["Health"])
    def health_check():
        return {"status": "healthy", "service": "rag-security-testbed"}

    return app


app = create_app()

