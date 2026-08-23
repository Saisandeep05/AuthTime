"""
FastAPI Reference Target Application Factory.
"""

import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.api.endpoints import router as api_router

def create_app() -> FastAPI:
    app = FastAPI(
        title="AuthTime Local Reference Target",
        description="Deliberately vulnerable FastAPI target app bound strictly to 127.0.0.1.",
        version="0.1.0"
    )
    app.include_router(api_router)

    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.exists(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    return app

app = create_app()
