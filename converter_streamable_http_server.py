# Unit Converter API + MCP (tools, resources, prompts)
# Uses FastAPI for HTTP routes and FastMCP to expose tools/resources/prompts over HTTP/SSE transports.
from fastapi import FastAPI, APIRouter
from fastmcp import FastMCP

from mcp_tools.converter_tools import (
    TOOL_DEFINITIONS,
    router as converter_router,
)
from mcp_prompts.converter_prompts import Investigate_IP_prompt, search_local_logs_prompt
from mcp_resources.converter_resources import AbuseIPDB, network_logs

from utils.resource_utils import register_resources
from utils.logging_utils import build_log_config

import platform
import datetime
import os
import time
from pathlib import Path
import uvicorn

# Set up your logging preferences 
# LOG_FILE = Path(r".\logs\mcp_log_streamable_http.log")(use forward slashes on mac/Linux too)
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
    title="SOC threat hunt MCP server",
    description="FastAPI endpoints auto-exposed as MCP tools via FastMCP, with resources and prompts.",
    version="1.2.1",
)

# --- Register Prompts ---
app.include_router(converter_router)
##app.include_router(mile_to_km)

# --- Register System ---
system_router = APIRouter(prefix="", tags=["system"])
started_at = time.time()

@system_router.get("/")
def root():
    return {
        "service": "unit-converter-mcp-server",
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

# FastMCP server generated from FastAPI OpenAPI (tools) plus manual resources/prompts
mcp = FastMCP.from_fastapi(
    app,
    name="Unit Converter MCP Server",
    instructions="Unit conversion tools with supporting resources and prompts.",
)

mcp.tool(
    name="lookup_ip_threat_intel",
    description="Convert kilometers to miles with one MCP progress notification.",
)

# converter_streamable_http_server.py

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

    print("Starting the Unit Converter API server (HTTP + MCP tools/resources/prompts)...")
    print(f"HTTP docs:      http://localhost:{PORT}/docs")
    print(f"HTTP redoc:     http://localhost:{PORT}/redoc")
    print(f"MCP endpoint:   http://localhost:{PORT}/mcp (HTTP)")

    uvicorn.run(
        app,
        host="localhost",
        port=PORT,
        log_level="trace",   # Uvicorn internal logging
        log_config=LOG_CONFIG,
    )
