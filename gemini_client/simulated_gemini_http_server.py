from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel, Field

from gemini_client.simulated_gemini_client import (
    GEMINI_MODEL,
    MCP_SERVER_URL,
    build_gemini_prompt,
    call_mcp_tool,
    generate_gemini_explanation,
    require_env,
)

load_dotenv()

app = FastAPI(
    title="Gemini MCP Client",
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
        "explain": "/explain",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "mcp_server_url": MCP_SERVER_URL,
        "gemini_model": GEMINI_MODEL,
    }


@app.post("/ip_triage")
async def explain(request: TriageRequest):
    return await run_full_triage(
        ip_address=request.ip_address,
        user_question=request.question,
    )
