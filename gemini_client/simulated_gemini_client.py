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
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "https://mcp-server-7vi1.onrender.com/mcp/")


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
    Send an MCP request to the deployed MCP server and return its response.

    The execution happens on the MCP server. This client only orchestrates the
    request/response flow and forwards the structured tool result to Gemini.
    """
    server_url = os.getenv("MCP_SERVER_URL", MCP_SERVER_URL)
    if server_url.endswith("/mcp"):
        server_url += "/"

    async with Client(
        server_url,
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
    if "log" in tool_name.lower():
        prompt_messages = search_local_logs_prompt(ip_address)
    else:
        prompt_messages = Investigate_IP_prompt(ip_address)

    sections = [
        "ROLE:\nYou are a Senior Security Operations Centre (SOC) Analyst assistant.\n"
        "Use the verified MCP tool result below as your source of truth."
    ]

    for message in prompt_messages:
        role_label = message.role.upper()
        content_text = getattr(message.content, "text", str(message.content))
        sections.append(f"{role_label}:\n{content_text}")

    sections.append(
        f"USER QUESTION:\n{user_question}\n\n"
        f"TARGET IP UNDER INVESTIGATION:\n{ip_address}\n\n"
        f"VERIFIED EVIDENCE FROM MCP SERVER:\n{mcp_result}\n\n"
        "FINAL INSTRUCTION:\n"
        "Synthesise this information into a concise, professional SOC triage report with clear recommendations."
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


async def run_prompt_workflow(
    prompt_name: str,
    ip_address: str,
    user_question: str,
) -> dict[str, Any]:
    """
    Execute the MCP tool corresponding to the chosen prompt workflow
    and synthesise the result with Gemini.
    """
    api_key = require_env(os.getenv("GEMINI_API_KEY", GEMINI_API_KEY), "GEMINI_API_KEY")
    model = os.getenv("GEMINI_MODEL", GEMINI_MODEL)

    # Map prompt name directly to the corresponding tool
    if prompt_name == "Search_local_logs":
        tool_name = "search_ip_in_logs_value"
    else:
        prompt_name = "Investigate_IP"
        tool_name = "lookup_ip_threat_intel"

    mcp_result, elapsed_ms = await call_mcp_tool(
        tool_name,
        {"ip_address": ip_address},
    )

    prompt = build_gemini_prompt(
        user_question=user_question,
        ip_address=ip_address,
        tool_name=tool_name,
        mcp_result=mcp_result,
    )

    explanation = generate_gemini_explanation(
        api_key=api_key,
        prompt=prompt,
        model=model,
    )

    return {
        "prompt_workflow": prompt_name,
        "tool_executed": tool_name,
        "ip_address": ip_address,
        "mcp_server_url": os.getenv("MCP_SERVER_URL", MCP_SERVER_URL),
        "mcp_elapsed_ms": round(elapsed_ms, 2),
        "mcp_result": mcp_result,
        "explanation": explanation,
    }


async def run_full_triage(
    ip_address: str,
    user_question: str,
    tool_name: str = "lookup_ip_threat_intel",
) -> dict[str, Any]:
    """Backward compatibility wrapper for run_prompt_workflow."""
    prompt_name = "Search_local_logs" if "log" in tool_name.lower() else "Investigate_IP"
    return await run_prompt_workflow(
        prompt_name=prompt_name,
        ip_address=ip_address,
        user_question=user_question,
    )


async def run_demo() -> None:
    """Run a local standalone demo of the IP triage flow."""
    target_ip = "118.25.6.39"
    question = f"What is the threat reputation of {target_ip} and should we block it?"

    print(f"Testing workflow 'Investigate_IP' for target: {target_ip}")
    result = await run_prompt_workflow("Investigate_IP", target_ip, question)

    print(f"\nMCP response received in {result['mcp_elapsed_ms']} ms:")
    print(result["mcp_result"])
    print(f"\nGemini Analysis:\n{result['explanation']}\n")


def main() -> None:
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
