"""FastAPI application entry point."""

import asyncio
import logging
import sys
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database.init_db import init_db
from routers.auth import router as auth_router
from routers.events import router as events_router
from routers.logs import router as logs_router
from routers.report import router as report_router
from routers.sessions import router as sessions_router

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

logging.basicConfig(level=logging.INFO)

TAGS_METADATA = [
    {"name": "auth", "description": "Google OAuth login and application JWT issuance."},
    {"name": "sessions", "description": "Create and inspect autonomous pentesting sessions."},
    {
        "name": "logs",
        "description": "Query an agent session's recorded log trail, stored in Elasticsearch.",
    },
]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Run startup and shutdown hooks for the application.

    Args:
        app: The FastAPI application instance.
    """
    await init_db()
    yield


app = FastAPI(
    title="ARES API",
    description="Autonomous Red-teaming & Exploitation System",
    version="0.1.0",
    lifespan=lifespan,
    openapi_tags=TAGS_METADATA,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(sessions_router, prefix="/sessions", tags=["sessions"])
app.include_router(report_router, prefix="/sessions", tags=["sessions"])
app.include_router(logs_router, prefix="/sessions", tags=["logs"])
app.include_router(events_router, prefix="/sessions", tags=["sessions"])
