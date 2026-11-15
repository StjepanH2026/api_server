# Conversion logic and HTTP endpoints are defined here so they can be reused
# by both the FastAPI app and the MCP tool registrations.

from __future__ import annotations

import os
import json
import ipaddress
from pathlib import Path
import requests
from fastapi import APIRouter, HTTPException, status

router = APIRouter(prefix="", tags=["soc-tools"])


# --- FastAPI endpoints & core tool logic --------------------------------------

@router.post("/lookup_ip_threat")
def lookup_ip_threat_intel(ip_address: str, maxAgeInDays: str = "30"):
    """
    Query an external threat intel API (AbuseIPDB).

    Args:
        ip_address: a valid IPv4 address to evaluate
        maxAgeInDays: maximum number of days for report history (default: 30)

    Returns:
        JSON dictionary containing the abuse confidence score, country, domain, etc.
    """
    try:
        ipaddress.IPv4Address(ip_address)
    except ipaddress.AddressValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"'{ip_address}' is not a valid IPv4 address.",
        )

    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="ABUSEIPDB_API_KEY environment variable is not configured.",
        )

    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        "ipAddress": ip_address,
        "maxAgeInDays": maxAgeInDays or "30",
    }
    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }

    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=10)
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to reach AbuseIPDB: {exc}",
        )

    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code,
            detail=f"AbuseIPDB returned error: {response.text}",
        )

    return response.json()


@router.post("/search_ip_in_logs")
def search_ip_in_logs_value(ip_address: str) -> str:
    """
    Search local logs for occurrences of specified IP address.

    Args:
        ip_address: Target IPv4 address to filter logs against

    Returns:
        Formatted string of log entries.
    """
    network_logs_path = (
        Path(__file__).resolve().parent.parent / "mcp_resources" / "Network_logs_sample.txt"
    )

    try:
        ipaddress.IPv4Address(ip_address)
    except ipaddress.AddressValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"'{ip_address}' is not a valid IPv4 address.",
        )

    if not network_logs_path.exists():
        return f"Error: Log file not found at {network_logs_path}"

    network_logs = network_logs_path.read_text(encoding="utf-8")
    results = network_logs.splitlines()

    matching_ip = [line for line in results if ip_address in line]

    if not matching_ip:
        return f"No network log entries for IP address {ip_address} found."

    return (
        f"Found {len(matching_ip)} entries for IP address {ip_address}:\n"
        + "\n".join(matching_ip)
    )


# --- Metadata for MCP tool registration ---------------------------------------

TOOL_DEFINITIONS = [
    {
        "name": "lookup_ip_threat_intel",
        "description": "Query an external threat intel API (AbuseIPDB) for an IP reputation score",
        "func": lookup_ip_threat_intel,
        "tags": {"IP", "threat"},
    },
    {
        "name": "search_ip_in_logs_value",
        "description": "Search local firewall and network logs for occurrences of specified IP address",
        "func": search_ip_in_logs_value,
        "tags": {"IP_address", "log_files"},
    },
]
