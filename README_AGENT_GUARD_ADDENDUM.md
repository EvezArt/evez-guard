# Agent Tool Security Gate (v0.3.0)

EVEZ Guard now includes an independent `agent_guard` module for pre-dispatch
policy decisions and hash-chained decision evidence. It is deliberately
separate from the existing gateway anti-abuse engine.

Quick start:

```python
from agent_guard import Guard, HashChainLedger

guard = Guard()
decision = guard.before_tool_call(
    session_id="session-123",
    tool="list_directory",
    arguments={"path": "/tmp"},
    call_id="call-456",
)
print(decision.action)  # allow / review / deny
```

See [the design and limits](docs/AGENT-TOOL-SECURITY-GATE.md) and
[Hermes integration contract](integrations/hermes/README.md).
