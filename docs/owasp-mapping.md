# OWASP Top 10 for Agentic Applications (2026): coverage in this repo

Source: [OWASP GenAI Security Project, published 9 December 2025](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026).

| ID | Risk | Covered here | How | What else you need in production |
|----|------|--------------|-----|----------------------------------|
| ASI01 | Agent Goal Hijack | Yes | Rule of Two, egress allowlist, sanitising, outbound filtering | Red-team tests with real models; content provenance from upstream systems |
| ASI02 | Tool Misuse & Exploitation | Yes | Least-privilege profiles, approval for destructive tools | Argument validation per tool, rate limits per user |
| ASI03 | Identity & Privilege Abuse | Partly | Per-task tool profiles | Agent identities in your IdP, short-lived scoped tokens, no shared service accounts |
| ASI04 | Agentic Supply Chain Vulnerabilities | Yes | Pinned tool fingerprints (`tools.lock.json`) | Curated MCP server allowlist, pinned package versions, SBOM |
| ASI05 | Unexpected Code Execution (RCE) | No | Not covered | Sandboxed execution (containers, no network by default), no `eval` of model output |
| ASI06 | Memory & Context Poisoning | Partly | Sanitising and provenance tags on untrusted input | Review and expiry of long-term memory; never write untrusted content to memory unreviewed |
| ASI07 | Insecure Inter-Agent Communication | No | Not covered | Authenticated, signed agent-to-agent messages; treat other agents' output as untrusted |
| ASI08 | Cascading Failures | Yes | Circuit breaker (per run and per tool) | Cost budgets, timeouts, kill switch |
| ASI09 | Human-Agent Trust Exploitation | Partly | Approval prompts state the reason and the exact call | Approval UX that shows data flows; training against approval fatigue |
| ASI10 | Rogue Agents | Partly | Audit log of every decision | SIEM integration, behavioural baselines, alerting on policy violations |
