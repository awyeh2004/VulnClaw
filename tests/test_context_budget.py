from __future__ import annotations

from types import SimpleNamespace

from vulnclaw.agent.context import ContextManager
from vulnclaw.agent.context_budget import build_context_budget, prepare_context
from vulnclaw.agent.token_counter import group_messages, truncate_message_groups
from vulnclaw.config.schema import VulnClawConfig
from vulnclaw.config.settings import _merge_config


def _agent(*, window: int = 900, max_tokens: int = 100):
    config = VulnClawConfig()
    config.llm.max_context_tokens = window
    config.llm.max_tokens = max_tokens
    config.session.context_auto_compact = True
    config.session.context_compact_trigger_ratio = 0.55
    config.session.context_compact_target_ratio = 0.40
    config.session.context_recent_message_groups = 2
    config.session.context_summary_max_tokens = 300
    context = ContextManager(max_history=1000)
    context.state.target = "example.test"
    context.state.agent_state.goal = "Verify a finding with evidence."
    context.state.agent_state.pin_fact("nginx observed on 443", evidence_id="e001")
    return SimpleNamespace(config=config, context=context)


def _tool_exchange(index: int) -> list[dict]:
    tool_id = f"call_{index}"
    return [
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": tool_id,
                    "type": "function",
                    "function": {"name": "fetch", "arguments": '{"url":"https://example.test"}'},
                }
            ],
        },
        {"role": "tool", "tool_call_id": tool_id, "content": f"status=200 result {index}"},
    ]


def test_group_truncation_keeps_assistant_tool_exchange_together():
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "older " * 120},
        *_tool_exchange(1),
        {"role": "user", "content": "latest request"},
    ]

    groups = group_messages(messages)
    assert len(groups) == 4
    assert len(groups[2]) == 2

    truncated = truncate_message_groups(messages, max_tokens=80, min_recent_groups=2)
    tool_messages = [message for message in truncated if message.get("role") == "tool"]
    assistants = [message for message in truncated if message.get("role") == "assistant"]
    assert bool(tool_messages) == bool(assistants)
    if tool_messages:
        assert tool_messages[0]["tool_call_id"] == assistants[0]["tool_calls"][0]["id"]


def test_prepare_context_compacts_history_and_records_durable_digest():
    agent = _agent()
    for index in range(10):
        agent.context.add_user_message(f"older observation {index}: " + "x" * 280)

    messages = [{"role": "system", "content": "system instructions"}, *agent.context.get_messages()]
    tools = [{"type": "function", "function": {"name": "fetch", "parameters": {"type": "object"}}}]

    result = prepare_context(agent, messages, tools, purpose="test")

    assert result.compacted is True
    assert result.after_tokens <= agent.config.llm.max_context_tokens - agent.config.llm.max_tokens
    assert result.removed_message_groups > 0
    assert agent.context.get_messages()[0]["content"].startswith("[context digest v1]")
    assert agent.context.state.agent_state.context_digest.summary.startswith("[context digest v1]")
    assert agent.context.state.agent_state.context_compactions[-1].purpose == "test"


def test_tool_schema_and_output_reserve_are_part_of_budget():
    agent = _agent(window=2000, max_tokens=300)
    messages = [{"role": "user", "content": "hello"}]
    tools = [
        {
            "type": "function",
            "function": {
                "name": "large_schema",
                "description": "x" * 400,
                "parameters": {"type": "object", "properties": {"payload": {"type": "string"}}},
            },
        }
    ]

    budget = build_context_budget(agent, messages, tools)

    assert budget is not None
    assert budget.tool_tokens > 0
    assert budget.total_input_tokens == budget.message_tokens + budget.tool_tokens
    assert budget.usable_input_tokens == 1700


def test_disabled_auto_compaction_preserves_history_until_hard_limit():
    agent = _agent(window=2000, max_tokens=100)
    agent.config.session.context_auto_compact = False
    agent.config.session.context_compact_trigger_ratio = 0.10
    for index in range(3):
        agent.context.add_user_message(f"history {index}: " + "x" * 180)
    messages = [{"role": "system", "content": "sys"}, *agent.context.get_messages()]

    result = prepare_context(agent, messages, [], purpose="disabled")

    assert result.compacted is False
    assert result.reason == ""
    assert not agent.context.state.agent_state.context_compactions


def test_legacy_solve_compaction_settings_migrate_to_global_policy():
    config = _merge_config(
        VulnClawConfig(),
        {
            "session": {
                "solve_auto_compact": False,
                "solve_compact_trigger_ratio": 0.42,
            }
        },
    )

    assert config.session.context_auto_compact is False
    assert config.session.context_compact_trigger_ratio == 0.42


def test_new_context_settings_take_precedence_over_legacy_aliases():
    config = _merge_config(
        VulnClawConfig(),
        {
            "session": {
                "solve_auto_compact": False,
                "solve_compact_trigger_ratio": 0.42,
                "context_auto_compact": True,
                "context_compact_trigger_ratio": 0.61,
            }
        },
    )

    assert config.session.context_auto_compact is True
    assert config.session.context_compact_trigger_ratio == 0.61
