"""Deterministic, deny-by-default policy decisions for proposed agent tool calls.

This module evaluates metadata supplied by a trusted tool dispatcher. It does not
inspect or execute shell commands, and it is not a substitute for OS sandboxing.
"""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath
from typing import Any, Mapping
import re

@dataclass(frozen=True)
class Decision:
    action: str
    reason: str
    rule_id: str
    tool: str
    call_id: str | None = None

@dataclass
class Policy:
    allowed_tools: set[str] = field(default_factory=lambda: {
        "read_file", "list_directory", "search", "http_get"
    })
    denied_tools: set[str] = field(default_factory=lambda: {
        "delete_file", "format_disk", "change_permissions", "shell"
    })
    credential_markers: tuple[str, ...] = (
        ".env", "id_rsa", "id_ed25519", "credentials", "secrets",
        "token", "private_key"
    )
    network_tools: set[str] = field(default_factory=lambda: {
        "http_get", "http_post", "browser", "send_email", "upload"
    })
    max_argument_chars: int = 16_384

    def evaluate(self, tool: str, arguments: Mapping[str, Any] | None,
                 *, call_id: str | None = None,
                 prior_sensitive_read: bool = False) -> Decision:
        args = arguments if isinstance(arguments, Mapping) else {}
        if not isinstance(tool, str) or not tool.strip():
            return Decision("deny", "Missing or invalid tool name", "EG-001", str(tool), call_id)
        if len(repr(args)) > self.max_argument_chars:
            return Decision("review", "Arguments exceed configured inspection limit", "EG-002", tool, call_id)
        if tool in self.denied_tools:
            return Decision("deny", "Tool is explicitly denied by policy", "EG-003", tool, call_id)
        if tool not in self.allowed_tools and tool not in self.network_tools:
            return Decision("review", "Tool is not explicitly classified", "EG-004", tool, call_id)

        rendered = repr(args).lower()
        if any(marker in rendered for marker in self.credential_markers):
            if tool in self.network_tools:
                return Decision("deny", "Credential-like material cannot be sent to a network tool", "EG-005", tool, call_id)
            if tool in self.allowed_tools:
                return Decision("review", "Credential-like path or value requires human review", "EG-006", tool, call_id)
        if prior_sensitive_read and tool in self.network_tools:
            return Decision("deny", "Network action follows a sensitive-read event in this session", "EG-007", tool, call_id)
        if tool in self.network_tools:
            return Decision("review", "Network-capable tool requires explicit approval", "EG-008", tool, call_id)
        return Decision("allow", "Tool is classified and no deny rule matched", "EG-000", tool, call_id)

def decide(tool: str, arguments: Mapping[str, Any] | None = None,
           *, policy: Policy | None = None, call_id: str | None = None,
           prior_sensitive_read: bool = False) -> dict[str, Any]:
    """Return a JSON-serializable decision. Unknown tools never auto-allow."""
    return asdict((policy or Policy()).evaluate(
        tool, arguments, call_id=call_id, prior_sensitive_read=prior_sensitive_read
    ))

class Guard:
    """Stateful session guard. Call before dispatch; record outcome after decision."""
    def __init__(self, policy: Policy | None = None):
        self.policy = policy or Policy()
        self._sensitive_read_sessions: set[str] = set()

    def before_tool_call(self, session_id: str, tool: str,
                         arguments: Mapping[str, Any] | None,
                         call_id: str | None = None) -> Decision:
        if not session_id:
            return Decision("deny", "Missing session identifier", "EG-009", tool, call_id)
        prior = session_id in self._sensitive_read_sessions
        result = self.policy.evaluate(tool, arguments, call_id=call_id,
                                      prior_sensitive_read=prior)
        if result.action == "allow" and tool in self.policy.allowed_tools:
            rendered = repr(arguments or {}).lower()
            if any(marker in rendered for marker in self.policy.credential_markers):
                self._sensitive_read_sessions.add(session_id)
        return result

    def reset_session(self, session_id: str) -> None:
        self._sensitive_read_sessions.discard(session_id)
