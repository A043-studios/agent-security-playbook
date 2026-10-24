"""agentguard - a teaching implementation of security controls for tool-using AI agents.

Companion code to the whitepaper "When Agents Act: A Security Playbook for Agentic AI"
by Tim Gelzleichter, A+43 Studios (2026).
"""

from .agent import Agent, RunResult
from .audit import AuditLog
from .guard import Guard, Policy, ToolIntegrityError, approve_all, console_approver, deny_all
from .model import GullibleModel
from .tools import Workspace, build_tools, load_manifest, write_manifest
from .types import Decision, FinalAnswer, Message, Task, ToolCall

__all__ = [
    "Agent", "RunResult", "AuditLog", "Guard", "Policy", "ToolIntegrityError",
    "approve_all", "console_approver", "deny_all", "GullibleModel", "Workspace",
    "build_tools", "load_manifest", "write_manifest", "Decision", "FinalAnswer",
    "Message", "Task", "ToolCall",
]

__version__ = "1.0.0"
