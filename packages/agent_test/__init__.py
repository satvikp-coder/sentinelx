"""sentinelx.agent_test: structured adapter-based evaluation of agent behavior in resettable labs.

Runs an agent adapter against a disposable lab copy in two arms:
  * unprotected (scripted planner baseline, no gateway enforcement)
  * protected (gateway enforcement before every action)

Everything is deterministic, local-only, and mock-free where possible.
"""

from .adapter import (
    Adapter,
    AdapterResult,
    ExecutableAdapter,
    HttpAdapter,
    ScriptedAdapter,
    load_adapter,
)
from .cli import agent_test_cmd
from .runner import (
    AgentTestConfig,
    AgentTestResult,
    run_agent_test,
    run_agent_test_sync,
)

__all__ = [
    "Adapter",
    "AdapterResult",
    "ScriptedAdapter",
    "ExecutableAdapter",
    "HttpAdapter",
    "load_adapter",
    "AgentTestConfig",
    "AgentTestResult",
    "run_agent_test",
    "run_agent_test_sync",
    "agent_test_cmd",
]
