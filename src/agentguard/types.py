"""Core data types shared by the agent, the model and the guard."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Role = Literal["system", "user", "assistant", "tool"]


@dataclass
class Message:
    """One entry in the agent's context window."""

    role: Role
    content: str
    source: str = ""
    # False for anything an outsider could have written (emails, web pages, tickets ...)
    trusted: bool = True


@dataclass
class ToolCall:
    """A tool invocation proposed by the model."""

    name: str
    args: dict[str, Any] = field(default_factory=dict)

    def short(self) -> str:
        if not self.args:
            return f"{self.name}()"
        parts = []
        for key, value in self.args.items():
            text = str(value).replace("\n", " ")
            if len(text) > 40:
                text = text[:37] + "..."
            parts.append(f"{key}={text}")
        return f"{self.name}({', '.join(parts)})"


@dataclass
class FinalAnswer:
    """The model's final reply to the user."""

    text: str


@dataclass
class Task:
    """What the user asked the agent to do, and under which permission profile."""

    goal: str
    owner_email: str
    profile: str


@dataclass
class Decision:
    """The guard's verdict on a proposed tool call."""

    allowed: bool
    control: str
    reason: str
    owasp: tuple[str, ...] = ()
    halt: bool = False  # stop the whole run (circuit breaker)
