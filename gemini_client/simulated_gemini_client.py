from __future__ import annotations

import asyncio
import json
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
    Instructs Gemini to return clean, structured JSON matching the SOC assessment schema.
    """
    if "log" in tool_name.lower():
        prompt_messages = search_local_logs_prompt(ip_address)
        schema_example = """{
  "verdict": "MALICIOUS / SUSPICIOUS / BENIGN / NO ACTIVITY",
  "threat_level": "CRITICAL / HIGH / MEDIUM / LOW / NONE",
  "activity_found": true,
  "executive_summary": "1-2 sentence executive summary of internal activity.",
  "evidence_analysis": "Detailed analysis of protocols, ports, and connection patterns observed in the logs.",
  "recommended_actions": [
    "Immediate firewall or network containment action",
    "Endpoint investigation or credential check"
  ]
}"""
    else:
        prompt_messages = Investigate_IP_prompt(ip_address)
        schema_example = """{
  "verdict": "CRITICAL / MALICIOUS / SUSPICIOUS / BENIGN",
  "threat_level": "CRITICAL / HIGH / MEDIUM / LOW / NONE",
  "abuse_confidence_score": 100,
  "country": "CN",
  "isp": "Internet Service Provider Name",
  "domain": "example.com",
  "total_reports": 952,
  "executive_summary": "1-2 sentence executive threat summary.",
  "evidence_analysis": "Detailed analysis of AbuseIPDB indicators, report volume, and attack types.",
  "recommended_actions": [
    "Perimeter Defense: Block IP at boundary firewalls",
    "SIEM Hunting: Search internal connection logs",
    "Host Containment: Isolate endpoints if bidirectional traffic occurred"
  ]
}"""

    sections = [
        "ROLE:\nYou are a Senior Security Operations Centre (SOC) Analyst assistant.",
        f"CRITICAL FORMATTING INSTRUCTION:\nYou must respond ONLY with a single valid JSON object matching this structure. Do not output markdown code blocks (no ```json or ```). Output raw JSON only:\n{schema_example}",
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
        "Populate the JSON fields accurately using the verified MCP evidence as your source of truth."
    )

    return "\n\n".join(sections)


def generate_gemini_explanation(
    *,
    api_key: str,
    prompt: str,
    model: str,
) -> str:
    """Request structured JSON from Gemini and return raw text."""
    from google import genai

    gemini_client = genai.Client(api_key=api_key)

    try:
        # Request native JSON formatting from Gemini
        response = gemini_client.models.generate_content(
            model=model,
            contents=prompt,
            config={"response_mime_type": "application/json"},
        )
        return response.text or "{}"
    except Exception:
        # Fallback to streaming if response_mime_type is unavailable
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
    and synthesise the result with Gemini into structured JSON.
    """
    api_key = require_env(os.getenv("GEMINI_API_KEY", GEMINI_API_KEY), "GEMINI_API_KEY")
    model = os.getenv("GEMINI_MODEL", GEMINI_MODEL)

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

    raw_explanation = generate_gemini_explanation(
        api_key=api_key,
        prompt=prompt,
        model=model,
    )

    # Clean any markdown fences if present
    cleaned = raw_explanation.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    if cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    cleaned = cleaned.strip()

    try:
        triage_assessment = json.loads(cleaned)
    except json.JSONDecodeError:
        triage_assessment = {
            "verdict": "PARSING_NOTICE",
            "raw_analysis": raw_explanation,
        }

    return {
        "prompt_workflow": prompt_name,
        "tool_executed": tool_name,
        "ip_address": ip_address,
        "mcp_server_url": os.getenv("MCP_SERVER_URL", MCP_SERVER_URL),
        "mcp_elapsed_ms": round(elapsed_ms, 2),
        "triage_assessment": triage_assessment,
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
    print(json.dumps(result, indent=2))


def main() -> None:
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
