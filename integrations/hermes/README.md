# Hermes Agent integration contract

EVEZ Guard exposes a deterministic pre-dispatch policy function. The integration
must call it at Hermes' documented `pre_tool_call` boundary, before any tool
executor is invoked. The exact hook registration/action schema must be matched
to the installed Hermes version; do not copy a guessed adapter signature.

## Required behavior

1. Obtain the canonical session ID, tool name, tool-call ID, and parsed arguments.
2. Call `Guard.before_tool_call(session_id, tool_name, arguments, call_id)`.
3. Map `allow` to continue; map `deny` to the hook's hard-block action; map
   `review` to the hook's human-approval action.
4. If the policy, ledger, or adapter raises or times out, block the tool call.
5. Append the decision metadata to `HashChainLedger` before returning the hook
   action. If evidence cannot be persisted, fail closed.
6. Never log prompts, credentials, raw arguments, or tool output.

## Minimal adapter pseudocode

```python
decision = guard.before_tool_call(session_id, tool_name, arguments, call_id)
ledger.append({
    "timestamp": utc_now(), "session_id": session_id, "call_id": call_id,
    "tool": tool_name, "action": decision.action, "reason": decision.reason,
    "rule_id": decision.rule_id,
})
if decision.action == "allow":
    return HERMES_CONTINUE
if decision.action == "review":
    return HERMES_REQUIRE_APPROVAL
return HERMES_BLOCK
```

The constants above are placeholders for the installed Hermes release's actual
hook contract. A live plugin compatibility test is required before claiming
drop-in integration. The core policy package itself has no third-party runtime
dependencies.
