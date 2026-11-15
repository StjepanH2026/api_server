from __future__ import annotations

import os
from enum import Enum
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel, Field

from gemini_client.simulated_gemini_client import (
    GEMINI_MODEL,
    MCP_SERVER_URL,
    run_prompt_workflow,
)

load_dotenv()

app = FastAPI(
    title="Gemini SOC MCP Client",
    description="HTTP wrapper for the Gemini client that invokes MCP prompts and tools.",
    version="1.1.0",
)


class PromptChoice(str, Enum):
    Investigate_IP = "Investigate_IP"
    Search_local_logs = "Search_local_logs"


class TriageRequest(BaseModel):
    question: str = Field(..., description="Analyst query for Gemini to answer.")
    ip_address: str = Field(..., description="Target IPv4 address to investigate.")


class DropdownTriageRequest(BaseModel):
    prompt_workflow: PromptChoice = Field(
        default=PromptChoice.Investigate_IP,
        description="Select the prompt workflow to run.",
    )
    question: str = Field(..., description="Analyst query for Gemini to answer.")
    ip_address: str = Field(..., description="Target IPv4 address to investigate.")


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    return {
        "service": "gemini-mcp-client",
        "status": "ok",
        "health": "/health",
        "docs": "/docs",
        "investigate_ip": "/Investigate_IP",
        "search_local_logs": "/Search_local_logs",
        "ip_triage": "/ip_triage",
    }


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "mcp_server_url": os.getenv("MCP_SERVER_URL", MCP_SERVER_URL),
        "gemini_model": os.getenv("GEMINI_MODEL", GEMINI_MODEL),
    }


@app.post(
    "/Investigate_IP",
    tags=["SOC Prompts"],
    summary="Investigate_IP – AbuseIPDB External Threat Reputation",
    description="Invokes the Investigate_IP prompt on the MCP server and queries AbuseIPDB for abuse score and reputation.",
)
async def investigate_ip_endpoint(request: TriageRequest) -> dict[str, Any]:
    return await run_prompt_workflow(
        prompt_name="Investigate_IP",
        ip_address=request.ip_address,
        user_question=request.question,
    )


@app.post(
    "/Search_local_logs",
    tags=["SOC Prompts"],
    summary="Search_local_logs – Local Network Log Investigation",
    description="Invokes the Search_local_logs prompt on the MCP server and filters local firewall/network logs for the IP.",
)
async def search_local_logs_endpoint(request: TriageRequest) -> dict[str, Any]:
    return await run_prompt_workflow(
        prompt_name="Search_local_logs",
        ip_address=request.ip_address,
        user_question=request.question,
    )


@app.post(
    "/ip_triage",
    tags=["SOC Prompts"],
    summary="ip_triage – Unified Prompt Selector",
    description="Select either Investigate_IP or Search_local_logs from the dropdown selector.",
)
async def ip_triage_dropdown(request: DropdownTriageRequest) -> dict[str, Any]:
    return await run_prompt_workflow(
        prompt_name=request.prompt_workflow.value,
        ip_address=request.ip_address,
        user_question=request.question,
    )
