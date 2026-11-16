"""HostGuard: an agentic host detection-and-response layer for a single Windows PC.

Microsoft Defender stays the real-time antivirus engine. HostGuard adds what a home PC is missing
compared with a commercial EDR: a compromise assessment (processes, network, persistence, logs,
files, memory), change tracking against a baseline, reversible containment with guardrails, a
real-time monitor, and an LLM agent that investigates findings with read-only tools.

Standard library only. Every state-changing action is logged and can be undone.
"""

__version__ = "0.1.0"
