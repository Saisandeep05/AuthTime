"""
FastAPI Application Factory for Reference Auth Target.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api.endpoints import router as api_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="AuthTime Reference Target",
        description="Deliberately realistic FastAPI reference app for authorization exposure measurement.",
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1", "http://localhost"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def add_correlation_id_header(request: Request, call_next):
        req_id = request.headers.get("X-AuthTime-Request-ID")
        response = await call_next(request)
        if req_id:
            response.headers["X-AuthTime-Request-ID"] = req_id
        return response

    app.include_router(api_router)
    return app


app = create_app()
