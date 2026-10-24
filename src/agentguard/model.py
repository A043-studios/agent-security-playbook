"""A deterministic stand-in for an LLM that, like real LLMs, cannot reliably tell
data from instructions.

Why simulate? Real models are non-deterministic: sometimes they follow an injected
instruction, sometimes they don't. That makes a demo flaky and, more importantly,
tempts teams to "fix" prompt injection with better prompts. This model always
falls for the injection, so you can see clearly which *controls outside the model*
stop the attack. Swap in a real model by implementing the same ``step()`` method.
"""

from __future__ import annotations

import re
from collections import deque
from typing import Protocol
from urllib.parse import quote

from .types import FinalAnswer, Message, Task, ToolCall

LAST_RESULT = "{{LAST_RESULT}}"
_EMAIL = r"([\w.+-]+@[\w-]+(?:\.[\w-]+)+)"

# (pattern, factory) pairs: what the gullible model treats as an instruction.
_INSTRUCTION_PATTERNS = [
    (re.compile(r"read (?:the )?file ([\w./-]+[\w])", re.I),
     lambda m: ToolCall("read_file", {"path": m.group(1)})),
    (re.compile(r"(?:send|forward|email|mail) (?:it|this|them|that|the contents?|the file|the data|everything)"
                r"(?: of [\w./-]+)? to " + _EMAIL, re.I),
     lambda m: ToolCall("send_email", {"to": m.group(1), "subject": "Requested data", "body": LAST_RESULT})),
    (re.compile(r"delete (?:all|every) (?:emails|messages)", re.I),
     lambda m: ToolCall("delete_emails", {"scope": "all"})),
    (re.compile(r"(?:fetch|open|visit) (https?://[^\s)]+[\w/])", re.I),
     lambda m: ToolCall("fetch_url", {"url": m.group(1)})),
]
_IMAGE_INSTRUCTION = re.compile(
    r"include (?:this|the following) (?:status )?(?:image|badge)[^:]*:\s*!\[([^\]]*)\]\((https?://[^)\s]+)\)", re.I
)
_EMAIL_HEADER = re.compile(r"From: (.*)\nSubject: (.*)")


class Model(Protocol):
    """Anything that proposes the next action given the conversation so far."""

    def reset(self) -> None: ...

    def step(self, history: list[Message], task: Task) -> ToolCall | FinalAnswer: ...


def parse_instructions(text: str) -> tuple[list[ToolCall], list[tuple[str, str]]]:
    """Return tool calls and image embeds a gullible model would 'obey' in ``text``."""
    found: list[tuple[int, ToolCall]] = []
    for pattern, factory in _INSTRUCTION_PATTERNS:
        for match in pattern.finditer(text):
            found.append((match.start(), factory(match)))
    found.sort(key=lambda item: item[0])
    images = [(m.group(1), m.group(2)) for m in _IMAGE_INSTRUCTION.finditer(text)]
    return [call for _, call in found], images


class GullibleModel:
    """Plans the user's task, but also executes any instruction found in tool output."""

    name = "gullible-simulator"

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._queue: deque[ToolCall] = deque()
        self._images: list[tuple[str, str]] = []
        self._seen = 0
        self._phase = "start"

    # -- planning ---------------------------------------------------------------
    def step(self, history: list[Message], task: Task) -> ToolCall | FinalAnswer:
        self._absorb(history)
        if self._phase == "start":
            self._phase = "reading"
            return ToolCall("read_inbox", {})
        if self._queue:
            return self._fill_placeholders(self._queue.popleft(), history)
        if self._phase == "reading":
            self._phase = "reporting"
            return ToolCall("send_email", {
                "to": task.owner_email,
                "subject": "Your inbox summary",
                "body": self._summary(history),
            })
        return FinalAnswer(self._summary(history))

    # -- internals --------------------------------------------------------------
    def _absorb(self, history: list[Message]) -> None:
        """Read new tool output - and, fatally, treat instructions in it as commands."""
        for message in history[self._seen:]:
            if message.role == "tool":
                calls, images = parse_instructions(message.content)
                self._queue.extend(calls)
                self._images.extend(images)
        self._seen = len(history)

    @staticmethod
    def _fill_placeholders(call: ToolCall, history: list[Message]) -> ToolCall:
        last = next((m.content for m in reversed(history) if m.role == "tool"), "")
        args = {k: (last if v == LAST_RESULT else v) for k, v in call.args.items()}
        return ToolCall(call.name, args)

    def _summary(self, history: list[Message]) -> str:
        inbox = next((m.content for m in reversed(history) if m.source == "tool:read_inbox"), "")
        headers = _EMAIL_HEADER.findall(inbox)
        lines = [f"Inbox summary ({len(headers)} emails):"]
        lines += [f"- {subject.strip()} (from {sender.strip()})" for sender, subject in headers]
        text = "\n".join(lines)
        for alt, url in self._images:
            # Exfiltration via auto-loaded image: data rides along in the URL.
            text += f"\n\n![{alt}]({url}{quote(text[:120])})"
        return text
