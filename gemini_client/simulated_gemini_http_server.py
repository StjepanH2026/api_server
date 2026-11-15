from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel, Field

from gemini_client.simulated_gemini_client import (
    GEMINI_MODEL,
    MCP_SERVER_URL,
    run_full_triage,
)

load_dotenv()

app = FastAPI(
    title="Gemini SOC MCP Client",
    description="HTTP wrapper for the Gemini client that calls the deployed MCP server.",
    version="1.0.0",
)


class TriageRequest(BaseModel):
    question: str = Field(..., description="Analyst triage query.")
    ip_address: str = Field(..., description="Target IPv4 address to investigate.")


@app.get("/")
def root() -> dict[str, str]:
    return {
        "service": "gemini-mcp-client",
        "status": "ok",
        "health": "/health",
        "triage": "/ip_triage",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "mcp_server_url": os.getenv("MCP_SERVER_URL", MCP_SERVER_URL),
        "gemini_model": os.getenv("GEMINI_MODEL", GEMINI_MODEL),
    }


@app.post("/ip_triage")
async def ip_triage(request: TriageRequest) -> dict[str, Any]:
    return await run_full_triage(
        ip_address=request.ip_address,
        user_question=request.question,
    )
