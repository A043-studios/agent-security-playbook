"""The policy enforcement point that sits between the model and its tools.

Principle: don't ask the model to be safe - make unsafe actions impossible or
supervised. Every control below is plain, deterministic code the model cannot
talk its way around.

Controls, in the order they run for each proposed tool call:

1. Circuit breaker      - cap tool calls per run and per tool       (OWASP ASI08)
2. Least privilege      - only tools in the task's profile           (ASI02, ASI03)
3. Egress allowlist     - recipients / URLs must be on the allowlist (ASI01, ASI02)
4. Rule of Two          - untrusted input + private data + external
                          action in one session needs a human         (ASI01, ASI06)
5. Human approval       - destructive tools always need a human      (ASI02, ASI09)

Plus, around the calls:

6. Input sanitising + provenance tagging for untrusted tool output    (ASI01, ASI06)
7. Outbound filtering of images/links to non-allowlisted domains     (ASI01)
8. Tool integrity check against a pinned manifest                    (ASI04)
9. Audit log of every decision                                        (ASI10)
"""

from __future__ import annotations

import re
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from .audit import AuditLog
from .sanitize import sanitize, wrap_untrusted
from .tools import DESTRUCTIVE, EXTERNAL_ACTION, RULE_OF_TWO, UNTRUSTED_INPUT, Tool
from .types import Decision, Task, ToolCall

Approver = Callable[[ToolCall, str], bool]


def deny_all(call: ToolCall, reason: str) -> bool:
    """Default approver for unattended runs: nobody is there to say yes."""
    return False


def approve_all(call: ToolCall, reason: str) -> bool:
    """For tests only - never use in production."""
    return True


def console_approver(call: ToolCall, reason: str) -> bool:
    answer = input(f"\n  APPROVAL NEEDED: {call.short()}\n  Reason: {reason}\n  Allow? [y/N] ")
    return answer.strip().lower() in {"y", "yes"}


class ToolIntegrityError(RuntimeError):
    """A tool definition differs from the reviewed, pinned version."""


@dataclass
class Policy:
    profiles: dict[str, set[str]]
    allowed_email_domains: set[str] = field(default_factory=set)
    allowed_url_domains: set[str] = field(default_factory=set)
    always_require_approval: set[str] = field(default_factory=set)
    rule_of_two: bool = True
    sanitize_inputs: bool = True
    filter_outbound: bool = True
    max_tool_calls: int = 12
    max_calls_per_tool: int = 4

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            profiles={name: set(p["allowed_tools"]) for name, p in data["profiles"].items()},
            allowed_email_domains=set(data["egress"]["allowed_email_domains"]),
            allowed_url_domains=set(data["egress"]["allowed_url_domains"]),
            always_require_approval=set(data["approval"]["always_require"]),
            rule_of_two=data["controls"]["rule_of_two"],
            sanitize_inputs=data["controls"]["sanitize_inputs"],
            filter_outbound=data["controls"]["filter_outbound"],
            max_tool_calls=data["limits"]["max_tool_calls"],
            max_calls_per_tool=data["limits"]["max_calls_per_tool"],
        )


_MD_IMAGE = re.compile(r"!\[([^\]]*)\]\(([^)\s]+)\)")
_MD_LINK = re.compile(r"(?<!!)\[([^\]]+)\]\(([^)\s]+)\)")


def _domain(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _domain_allowed(domain: str, allowed: set[str]) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in allowed)


class Guard:
    def __init__(
        self,
        policy: Policy,
        tools: dict[str, Tool],
        approver: Approver = deny_all,
        audit: AuditLog | None = None,
        manifest: dict[str, str] | None = None,
    ) -> None:
        self.policy = policy
        self.tools = tools
        self.approver = approver
        self.audit = audit or AuditLog()
        if manifest is not None:
            self._verify_manifest(manifest)
        self.start(Task(goal="", owner_email="", profile=""))

    # -- session ---------------------------------------------------------------
    def start(self, task: Task) -> None:
        self.task = task
        self.session_caps: set[str] = set()
        self.calls = 0
        self.per_tool: Counter[str] = Counter()
        if task.goal:
            self.audit.record("run_started", goal=task.goal, profile=task.profile)

    # -- control 8: supply chain -------------------------------------------------
    def _verify_manifest(self, manifest: dict[str, str]) -> None:
        problems = []
        for name, tool in self.tools.items():
            pinned = manifest.get(name)
            if pinned is None:
                problems.append(f"{name}: not in reviewed manifest")
            elif pinned != tool.fingerprint():
                problems.append(f"{name}: definition changed since review")
        if problems:
            self.audit.record("tool_integrity_failed", problems=problems, owasp=["ASI04"])
            raise ToolIntegrityError("; ".join(problems))
        self.audit.record("tool_integrity_ok", tools=sorted(self.tools))

    # -- controls 1-5: authorise each call ----------------------------------------
    def call_capabilities(self, tool: Tool, call: ToolCall) -> frozenset[str]:
        """Capabilities of this particular call.

        Sending a result back to the task's own principal is not external
        communication: the data flows to someone already entitled to it.
        """
        caps = tool.capabilities
        if tool.reply_arg and str(call.args.get(tool.reply_arg, "")).lower() == self.task.owner_email.lower():
            caps = caps - {EXTERNAL_ACTION}
        return caps

    def authorize(self, call: ToolCall) -> Decision:
        decision = self._decide(call)
        if decision.allowed:
            tool = self.tools.get(call.name)
            if tool:
                self.session_caps |= self.call_capabilities(tool, call) & RULE_OF_TWO
        self.audit.record(
            "tool_call",
            tool=call.name,
            args={k: str(v)[:200] for k, v in call.args.items()},
            allowed=decision.allowed,
            control=decision.control,
            reason=decision.reason,
            owasp=list(decision.owasp),
        )
        return decision

    def _decide(self, call: ToolCall) -> Decision:
        p = self.policy
        self.calls += 1
        self.per_tool[call.name] += 1

        # 1. Circuit breaker
        if self.calls > p.max_tool_calls or self.per_tool[call.name] > p.max_calls_per_tool:
            return Decision(False, "circuit_breaker",
                            f"call budget exceeded ({self.calls} total, {self.per_tool[call.name]} x {call.name})",
                            ("ASI08",), halt=True)

        tool = self.tools.get(call.name)
        if tool is None:
            return Decision(False, "least_privilege", f"unknown tool '{call.name}'", ("ASI02",))

        # 2. Least privilege
        allowed_tools = p.profiles.get(self.task.profile, set())
        if call.name not in allowed_tools:
            return Decision(False, "least_privilege",
                            f"'{call.name}' is not in profile '{self.task.profile}'", ("ASI02", "ASI03"))

        # 3. Egress allowlist
        if "to" in call.args:
            domain = str(call.args["to"]).rsplit("@", 1)[-1].lower()
            if not _domain_allowed(domain, p.allowed_email_domains):
                return Decision(False, "egress_allowlist",
                                f"recipient domain '{domain}' is not allowlisted", ("ASI01", "ASI02"))
        if "url" in call.args:
            domain = _domain(str(call.args["url"]))
            if not _domain_allowed(domain, p.allowed_url_domains):
                return Decision(False, "egress_allowlist",
                                f"URL domain '{domain}' is not allowlisted", ("ASI01", "ASI02"))

        # 4. Rule of Two: never all of untrusted input + private data + external action, unsupervised
        if p.rule_of_two:
            would_have = self.session_caps | (self.call_capabilities(tool, call) & RULE_OF_TWO)
            if would_have >= RULE_OF_TWO:
                return self._ask_human(call, "Rule of Two: session would combine untrusted input, "
                                             "private data and an external action", ("ASI01", "ASI06"))

        # 5. Human approval for destructive / listed tools
        if DESTRUCTIVE in tool.capabilities or call.name in p.always_require_approval:
            return self._ask_human(call, f"'{call.name}' is destructive and always needs approval",
                                   ("ASI02", "ASI09"))

        return Decision(True, "policy", "within policy")

    def _ask_human(self, call: ToolCall, reason: str, owasp: tuple[str, ...]) -> Decision:
        approved = self.approver(call, reason)
        verdict = "approved by human" if approved else "denied: no human approval"
        return Decision(approved, "human_approval", f"{reason} -> {verdict}", owasp)

    # -- control 6: what comes back from tools -------------------------------------
    def ingest(self, call: ToolCall, output: str) -> str:
        tool = self.tools[call.name]
        if UNTRUSTED_INPUT not in tool.capabilities or not self.policy.sanitize_inputs:
            return output
        cleaned, report = sanitize(output)
        if not report.clean:
            self.audit.record("input_sanitized", tool=call.name, removed=report.removed,
                              flags=report.flags, owasp=["ASI01", "ASI06"])
        return wrap_untrusted(cleaned, source=f"tool:{call.name}")

    # -- control 7: what leaves the agent ---------------------------------------------
    def filter_outbound_text(self, text: str, where: str = "final answer") -> str:
        if not self.policy.filter_outbound:
            return text
        allowed = self.policy.allowed_url_domains
        removed: list[str] = []

        def strip_image(match: re.Match) -> str:
            domain = _domain(match.group(2))
            if _domain_allowed(domain, allowed):
                return match.group(0)
            removed.append(domain)
            return f"[image removed: {domain} is not allowlisted]"

        def strip_link(match: re.Match) -> str:
            domain = _domain(match.group(2))
            if _domain_allowed(domain, allowed):
                return match.group(0)
            removed.append(domain)
            return f"{match.group(1)} [link removed: {domain}]"

        text = _MD_IMAGE.sub(strip_image, text)
        text = _MD_LINK.sub(strip_link, text)
        if removed:
            self.audit.record("outbound_filtered", where=where, domains=sorted(set(removed)), owasp=["ASI01"])
        return text

    def filter_outbound_call(self, call: ToolCall) -> ToolCall:
        tool = self.tools.get(call.name)
        if not tool or EXTERNAL_ACTION not in tool.capabilities:
            return call
        args = {k: self.filter_outbound_text(v, where=f"{call.name}.{k}") if isinstance(v, str) and k != "to" else v
                for k, v in call.args.items()}
        return ToolCall(call.name, args)
