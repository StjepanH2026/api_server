from __future__ import annotations

from fastmcp.prompts import Message


def Investigate_IP_prompt(ip_address: str) -> list[Message]:
    """Guiding prompt for IP threat reputation triage."""
    system_instructions = (
        "You are a Security Operations Centre (SOC) Analyst. When given an IP address, perform a complete triage:\n"
        "1. Call the 'lookup_ip_threat_intel' tool to query AbuseIPDB for the target IP\n"
        "2. Interpret the returned abuse confidence score, ISP, and country of origin\n"
        "3. Provide a clear threat assessment for the user\n"
        "4. List the following data clearly: ipaddress, abuseConfidenceScore, country, isp, domain, totalReports, lastReportedAt."
    )
    user_instructions = f"Perform a threat analysis for the following IP address: {ip_address}."

    return [
        Message(role="assistant", content=system_instructions),
        Message(role="user", content=user_instructions),
    ]


def search_local_logs_prompt(ip_address: str) -> list[Message]:
    """Guiding prompt for local network log investigation."""
    system_instructions = (
        "You are a Security Operations Centre (SOC) Analyst. When given an IP address:\n"
        "1. Invoke the 'search_ip_in_logs_value' tool using the provided IP address\n"
        "2. Parse the returned log entries and present a clear chronological timeline of events\n"
        "3. Highlight key details such as timestamp, protocol/port, username, and success/fail status\n"
        "4. State whether you believe this activity to be benign or a threat."
    )
    user_instructions = f"Search network logs for activity related to IP address: {ip_address}."

    return [
        Message(role="assistant", content=system_instructions),
        Message(role="user", content=user_instructions),
    ]


PROMPT_DEFINITIONS = [
    {
        "name": "Investigate_IP",
        "description": (
            "Query AbuseIPDB for an IP address threat score and reputation."
        ),
        "func": Investigate_IP_prompt,
    },
    {
        "name": "Search_local_logs",
        "description": (
            "Take user's entered IP address and search the local network log directory for matching activity."
        ),
        "func": search_local_logs_prompt,
    },
]