"""
FastAPI Reference Target Application Factory.
"""

from fastapi import FastAPI
from app.api.endpoints import router as api_router

def create_app() -> FastAPI:
    app = FastAPI(
        title="AuthTime Local Reference Target",
        description="Deliberately vulnerable FastAPI target app bound strictly to 127.0.0.1.",
        version="0.1.0"
    )
    app.include_router(api_router)
    return app

app = create_app()
