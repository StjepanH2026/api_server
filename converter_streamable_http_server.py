# SOC Threat Hunt API + MCP (tools, resources, prompts)
# Uses FastAPI for HTTP routes and FastMCP to expose tools/resources/prompts over HTTP/SSE transports.

from __future__ import annotations

import os
import time
import platform
import datetime
from pathlib import Path

from dotenv import load_dotenv

# Load local .env variables before anything else
load_dotenv()

from fastapi import FastAPI, APIRouter
from fastmcp import FastMCP

from mcp_tools.converter_tools import (
    TOOL_DEFINITIONS,
    router as converter_router,
)
from mcp_prompts.converter_prompts import Investigate_IP_prompt, search_local_logs_prompt
from mcp_resources.converter_resources import AbuseIPDB, network_logs

from utils.logging_utils import build_log_config

# Set up logging preferences
LOG_FILE = Path("logs/mcp_log_streamable_http.log")

LOG_CONFIG = build_log_config(
    LOG_FILE,
    logger_handlers={
        "uvicorn": ["rotating_file", "console"],
        "uvicorn.error": ["rotating_file", "console"],
        "uvicorn.access": ["rotating_file"],
    },
    root_level="INFO",
    logger_level="DEBUG",
)

# FastAPI app for plain HTTP
app = FastAPI(
    title="SOC Threat Hunt MCP Server",
    description="FastAPI endpoints auto-exposed as MCP tools via FastMCP, with resources and prompts.",
    version="1.2.1",
)

# --- Register Routers ---
app.include_router(converter_router)

# --- Register System Routes ---
system_router = APIRouter(prefix="", tags=["system"])
started_at = time.time()


@system_router.get("/")
def root():
    return {
        "service": "soc-threat-hunt-mcp-server",
        "status": "ok",
        "docs": "/docs",
        "health": "/health",
        "mcp": "/mcp/",
    }


@system_router.get("/health")
def health():
    return {
        "status": "ok",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "pid": os.getpid(),
        "cwd": os.getcwd(),
        "uptime_seconds": round(time.time() - started_at, 2),
    }


app.include_router(system_router)

# FastMCP server generated from FastAPI OpenAPI plus manual resources/prompts
mcp = FastMCP.from_fastapi(
    app,
    name="SOC Threat Hunt MCP Server",
    instructions="Security Operations Centre triage tools with supporting resources and prompts.",
)

# Register MCP tools with exact, clean tool names
for tool in TOOL_DEFINITIONS:
    mcp.tool(
        name=tool["name"],
        description=tool["description"],
    )(tool["func"])


# --- Register static resources ---
@mcp.resource("resource://AbuseIPDB", name="AbuseIP Database", mime_type="application/json")
def _resource_AbuseIPDB():
    return AbuseIPDB()


@mcp.resource("resource://network_logs", name="Network Logs", mime_type="text/plain")
def _resource_network_logs():
    return network_logs()


# --- Register prompts ---
@mcp.prompt(name="Investigate_IP", description="Query AbuseIPDB for an IP address abuse score.")
def _prompt_Investigate_IP(ip_address: str):
    return Investigate_IP_prompt(ip_address)


@mcp.prompt(name="Search_local_logs", description="Search local network logs for IP activity.")
def _prompt_Search_local_logs(ip_address: str):
    return search_local_logs_prompt(ip_address)


# Build MCP sub-application and mount onto FastAPI
mcp_http_app = mcp.http_app(path="/", transport="streamable-http")

# Ensure FastAPI runs the MCP lifespan so streamable-http initialises properly
app.router.lifespan_context = mcp_http_app.lifespan

app.mount("/mcp", mcp_http_app)

if __name__ == "__main__":
    import uvicorn

    PORT = 8003

    print("Starting the SOC Threat Hunt API server (HTTP + MCP tools/resources/prompts)...")
    print(f"HTTP docs:      http://localhost:{PORT}/docs")
    print(f"HTTP redoc:     http://localhost:{PORT}/redoc")
    print(f"MCP endpoint:   http://localhost:{PORT}/mcp (HTTP)")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        log_config=LOG_CONFIG,
    )
