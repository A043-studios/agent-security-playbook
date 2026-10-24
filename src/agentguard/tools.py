"""A small simulated workspace (inbox, files, outbox) and the tools an agent can call.

Every tool declares its *capabilities*. The guard uses them to apply the
"Agents Rule of Two" (Meta, 2025) / "lethal trifecta" (Willison, 2025):

    [A] UNTRUSTED_INPUT  - reads content an outsider could control
    [B] PRIVATE_DATA     - reads sensitive systems or private data
    [C] EXTERNAL_ACTION  - changes state or communicates externally

A session that combines all three must not run unsupervised.

Two modelling choices follow the accompanying paper:
- An inbox is both untrusted (anyone can write to it) and private (it holds
  customer correspondence), so ``read_inbox`` carries [A] and [B].
- A reply to the task's own principal is not external communication, so a
  tool can name a ``reply_arg``; calls addressed to the principal drop [C].
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

UNTRUSTED_INPUT = "untrusted_input"
PRIVATE_DATA = "private_data"
EXTERNAL_ACTION = "external_action"
DESTRUCTIVE = "destructive"

RULE_OF_TWO = frozenset({UNTRUSTED_INPUT, PRIVATE_DATA, EXTERNAL_ACTION})


@dataclass
class Tool:
    name: str
    description: str
    capabilities: frozenset[str]
    fn: Callable[..., str]
    reply_arg: str | None = None  # argument that names the recipient, if any

    def fingerprint(self) -> str:
        """Hash of everything the model sees about this tool.

        If a tool (or MCP server) silently changes its description - a "rug pull"
        or tool-poisoning attack - the fingerprint changes too.
        """
        payload = json.dumps(
            {
                "name": self.name,
                "description": self.description,
                "capabilities": sorted(self.capabilities),
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class Workspace:
    """Fake company environment the agent operates on. Nothing here touches the network."""

    inbox: list[dict]
    files: dict[str, str]
    outbox: list[dict] = field(default_factory=list)
    http_log: list[str] = field(default_factory=list)
    deleted: list[dict] = field(default_factory=list)

    @classmethod
    def from_dir(cls, root: str | Path) -> "Workspace":
        root = Path(root)
        inbox = json.loads((root / "inbox.json").read_text(encoding="utf-8"))
        files = {}
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.name != "inbox.json":
                files[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8")
        return cls(inbox=inbox, files=files)

    def emails_sent_to(self, domain: str) -> list[dict]:
        return [m for m in self.outbox if m["to"].lower().endswith("@" + domain.lower())]


def build_tools(ws: Workspace) -> dict[str, Tool]:
    """Create the tool set bound to one workspace."""

    def read_inbox() -> str:
        if not ws.inbox:
            return "Inbox is empty."
        blocks = []
        for mail in ws.inbox:
            blocks.append(
                f"--- Email {mail['id']} ---\n"
                f"From: {mail['from']}\n"
                f"Subject: {mail['subject']}\n\n"
                f"{mail['body']}"
            )
        return "\n\n".join(blocks)

    def read_file(path: str) -> str:
        return ws.files.get(path, f"File not found: {path}")

    def send_email(to: str, subject: str, body: str) -> str:
        ws.outbox.append({"to": to, "subject": subject, "body": body})
        return f"Email sent to {to}."

    def delete_emails(scope: str = "all") -> str:
        count = len(ws.inbox)
        ws.deleted.extend(ws.inbox)
        ws.inbox.clear()
        return f"Deleted {count} emails."

    def fetch_url(url: str) -> str:
        ws.http_log.append(url)
        return f"(simulated) fetched {url}"

    tools = [
        Tool("read_inbox", "Read all emails in the shared support inbox.",
             frozenset({UNTRUSTED_INPUT, PRIVATE_DATA}), read_inbox),
        Tool("read_file", "Read a file from the company file share.",
             frozenset({PRIVATE_DATA}), read_file),
        Tool("send_email", "Send an email on behalf of the user.",
             frozenset({EXTERNAL_ACTION}), send_email, reply_arg="to"),
        Tool("delete_emails", "Delete emails from the inbox.",
             frozenset({EXTERNAL_ACTION, DESTRUCTIVE}), delete_emails),
        Tool("fetch_url", "Fetch a web page.",
             frozenset({UNTRUSTED_INPUT, EXTERNAL_ACTION}), fetch_url),
    ]
    return {tool.name: tool for tool in tools}


def write_manifest(tools: dict[str, Tool], path: str | Path) -> None:
    """Pin the reviewed tool definitions (like a lock file for dependencies)."""
    manifest = {name: tool.fingerprint() for name, tool in sorted(tools.items())}
    Path(path).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def load_manifest(path: str | Path) -> dict[str, str]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
