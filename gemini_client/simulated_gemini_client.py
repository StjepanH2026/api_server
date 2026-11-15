from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from dotenv import load_dotenv
from fastmcp import Client

from mcp_prompts.converter_prompts import Investigate_IP_prompt, search_local_logs_prompt

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "https://mcp-server-7vi1.onrender.com")

KM_TO_MILES_TOOL = "kilometers_to_miles"


def require_env(value: str | None, name: str) -> str:
    """Return an environment variable or raise a clear error."""
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


async def handle_mcp_progress(
    progress: float,
    total: float | None,
    message: str | None,
) -> None:
    """Print MCP progress notifications so they are visible during the demo."""

    if total is None:
        progress_text = f"{progress}"
    else:
        progress_text = f"{progress}/{total}"

    print(f"[MCP progress] {progress_text}: {message or 'update'}")


async def call_mcp_tool(tool_name: str, arguments: dict[str, Any]) -> tuple[Any, float]:
    """
    Send an MCP request to the existing converter MCP server and return its response.

    The calculation happens on the MCP server. This client only orchestrates the
    request/response flow and forwards the structured tool result to Gemini.
    """

    async with Client(
        MCP_SERVER_URL,
        auth="demo-token",
        progress_handler=handle_mcp_progress,
    ) as mcp_client:
        started_at = time.perf_counter()
        result = await mcp_client.call_tool(tool_name, arguments)
        elapsed_ms = (time.perf_counter() - started_at) * 1000

    return result, elapsed_ms


def build_gemini_prompt(
    user_question: str,
    ip_address: str,
    tool_name: str,
    mcp_result: Any,
) -> str:
    """
    Build the model context sent to Gemini.
    Selects the relevant SOC prompt based on the tool that was invoked.
    """
    # Select the prompt matching the tool call
    if "log" in tool_name.lower():
        prompt_messages = search_local_logs_prompt(ip_address)
    else:
        prompt_messages = Investigate_IP_prompt(ip_address)

    sections = [
        "NOTE: You are acting as an automated SOC Analyst assistant. "
        "Use the verified MCP tool result below as your source of truth."
    ]

    # FastMCP Message content can be a TextContent object or plain string
    for message in prompt_messages:
        role_label = message.role.upper()
        content_text = getattr(message.content, "text", str(message.content))
        sections.append(f"{role_label}:\n{content_text}")

    sections.append(
        f"USER QUESTION:\n{user_question}\n\n"
        f"TARGET IP:\n{ip_address}\n\n"
        f"VERIFIED MCP TOOL RESULT:\n{mcp_result}\n\n"
        "Synthesise this information into a concise, professional SOC triage report."
    )

    return "\n\n".join(sections)


def generate_gemini_explanation(
    *,
    api_key: str,
    prompt: str,
    model: str,
) -> str:
    """Stream Gemini output and return the combined explanation text."""

    from google import genai

    gemini_client = genai.Client(api_key=api_key)
    stream = gemini_client.models.generate_content_stream(
        model=model,
        contents=prompt,
    )

    chunks: list[str] = []
    for chunk in stream:
        if chunk.text:
            chunks.append(chunk.text)

    return "".join(chunks).strip()


async def run_demo() -> None:
    api_key = require_env(GEMINI_API_KEY, "GEMINI_API_KEY")

    target_ip = "118.25.6.39"
    tool_name = "lookup_ip_threat_intel"
    user_question = f"What is the threat reputation of {target_ip} and should we block it?"

    print(f"User Question: {user_question}")
    print(f"Calling MCP Tool: {tool_name}")

    mcp_result, elapsed_ms = await call_mcp_tool(
        tool_name,
        {"ip_address": target_ip},
    )

    print(f"MCP structured result ({elapsed_ms:.2f} ms):\n{mcp_result}")

    prompt = build_gemini_prompt(
        user_question=user_question,
        ip_address=target_ip,
        tool_name=tool_name,
        mcp_result=mcp_result,
    )

    explanation = generate_gemini_explanation(
        api_key=api_key,
        prompt=prompt,
        model=GEMINI_MODEL,
    )

    print(f"\nGemini SOC Analysis:\n{explanation}\n")


def main() -> None:
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
