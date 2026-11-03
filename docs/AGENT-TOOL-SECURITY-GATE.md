# EVEZ Guard Agent Tool Security Gate — v0.3.0

## Purpose
A local-first, deterministic policy component for evaluating proposed AI-agent
tool calls before dispatch. It complements the existing EVEZ Gateway Guard;
it does not replace API authentication, rate limiting, OS sandboxing, or human
approval.

## Decision contract
- **allow**: explicitly classified, low-risk action.
- **review**: unknown or network-capable action, oversized input, or sensitive
  path/value requiring a human decision.
- **deny**: explicitly prohibited action, credential-to-network pattern, missing
  session identity, or failed evidence persistence.

Unknown tools never auto-allow. Network-capable tools require approval by
default. A reviewed action is not assumed to have executed.

## Evidence
The JSONL ledger stores only decision metadata and links records with SHA-256.
It refuses writes when its configured capacity is reached; it never silently
rotates or overwrites evidence. SHA-256 chaining detects accidental or
unsophisticated modification, but is not a digital signature and does not
prove who created a record. Protect the ledger directory with OS permissions
and export periodic signed manifests for stronger provenance.

## Run tests
```bash
python -m unittest discover -s tests -v
```

## Limits
The policy is a guardrail, not a complete sandbox. It cannot prove that every
tool route is intercepted. Its path and argument checks are heuristic. A
production integration must bind to the exact Hermes hook API, enforce
fail-closed behavior, and test every registered executor and alternate
dispatch route on the target version.
