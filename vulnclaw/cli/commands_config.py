"""``vulnclaw config`` —— 配置管理子命令组（get/set/list/provider/model + 交互式面板）。

从 :mod:`vulnclaw.cli.main` 拆出（2026-10-12）。模块自带 ``config_app``，
``main.py`` 用 ``app.add_typer(config_app, name="config")`` 注册（与 evidence_cmd 同约定）。

``load_config`` 一律经 :func:`vulnclaw.cli.repl._from_main` 在**调用时**解析：
测试把 ``load_config`` patch 在 ``cli.main`` 上（32 处），直接读本模块的 import 副本会
让补丁静默失效。
"""

from __future__ import annotations

from typing import Optional

import typer

from vulnclaw.cli._helpers import console, err_console
from vulnclaw.cli.repl import _from_main
from vulnclaw.config.settings import (
    apply_provider_preset,
    list_providers,
    save_config,
    set_config_value,
)
from vulnclaw.config.token_provider import has_llm_credentials


config_app = typer.Typer(help="Manage configuration")


@config_app.callback(invoke_without_command=True)
def config_root(ctx: typer.Context) -> None:
    """Open the interactive config editor when no subcommand is provided."""
    if ctx.resilient_parsing or ctx.invoked_subcommand is not None:
        return
    from vulnclaw.cli.tui import run_config_tui

    run_config_tui()


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Config key in dot notation, e.g. llm.api_key"),
    value: str = typer.Argument(..., help="Config value"),
) -> None:
    """Set a config value."""
    set_config_value(key, value)
    console.print(
        f"[+] Set {key} = {'***' if 'key' in key.lower() or 'pass' in key.lower() else value}"
    )


@config_app.command("get")
def config_get(
    key: str = typer.Argument(..., help="Config key in dot notation"),
) -> None:
    """Get a config value.

    The traversal lives in :func:`get_config_value`, because ``config get`` is not the
    only reader and the shapes differ: ``platforms.ctf2.enabled`` and
    ``mcp.servers.chrome-devtools.enabled`` sit in dicts / ``extra="allow"`` sections,
    which a bare ``getattr`` chain cannot reach. A missing key is an operator error,
    not a crash: report it and exit non-zero.
    """
    from vulnclaw.config.settings import get_config_value

    try:
        value = get_config_value(key)
    except KeyError:
        err_console.print(f"[red]未知配置键：{key}[/red]")
        raise typer.Exit(2) from None
    value = value if not hasattr(value, "model_dump") else value.model_dump()
    if isinstance(value, str) and ("key" in key.lower() or "pass" in key.lower()):
        value = value[:8] + "..." if len(value) > 8 else "***"
    console.print(f"{key} = {value}")


@config_app.command("list")
def config_list() -> None:
    """List all configuration values."""
    import yaml as _yaml

    config = _from_main("load_config")()
    raw = config.model_dump(mode="json")
    console.print(_yaml.dump(raw, default_flow_style=False, allow_unicode=True))


@config_app.command("provider")
def config_provider(
    name: Optional[str] = typer.Argument(
        None, help="Provider name to switch to (e.g. minimax, deepseek)"
    ),
    list_all: bool = typer.Option(False, "--list", "-l", help="List all available providers"),
) -> None:
    """View or switch the configured LLM provider."""
    if list_all or name is None:
        providers = list_providers()
        current_config = _from_main("load_config")()
        current_provider = current_config.llm.provider

        console.print("[bold]Available LLM Providers[/]")
        console.print()
        for p in providers:
            is_current = p["provider"] == current_provider
            marker = " [green](current)[/]" if is_current else ""
            console.print(f"  [bold cyan]{p['provider']}[/]{marker}")
            console.print(f"    Label: {p['label']}")
            console.print(f"    URL:  [dim]{p['base_url']}[/]")
            console.print(f"    Model: [dim]{p['default_model']}[/]")
            console.print()
        console.print("[dim]Use vulnclaw config provider <name> to switch providers.[/]")
        return

    # Switch provider
    from vulnclaw.config.schema import PROVIDER_PRESETS, LLMProvider

    # Validate provider name
    try:
        provider_enum = LLMProvider(name.lower())
    except ValueError:
        console.print(f"[!] Unknown provider: [bold]{name}[/]")
        console.print(f"    Available: {', '.join(p.value for p in LLMProvider)}")
        console.print("    Tip: use [bold]custom[/] for a manual base_url and model.")
        raise typer.Exit(1)

    config = _from_main("load_config")()
    config = apply_provider_preset(config, name.lower())
    save_config(config)

    preset = PROVIDER_PRESETS.get(provider_enum, {})
    label = preset.get("label", name)
    console.print(f"[+] Switched LLM provider to [bold cyan]{label}[/]")
    console.print(f"    Base URL: [dim]{config.llm.base_url}[/]")
    console.print(f"    Model:    [dim]{config.llm.model}[/]")

    if not has_llm_credentials(config.llm):
        console.print()
        console.print(
            "[yellow]Set credentials first: [bold]vulnclaw config set llm.api_key <your-key>[/] "
            "or configure keyless auth (llm.auth_mode = env/file/command/wif)[/]"
        )


@config_app.command("model")
def config_model(
    name: Optional[str] = typer.Argument(
        None, help="Model alias: zhipu | ds (shallow), or bare"
    ),
    level: Optional[str] = typer.Argument(
        None, help="Thinking level: low | high | max (default: low)"
    ),
    deep: bool = typer.Option(
        False, "--deep", "-d", help="Use the provider's deeper model (ds -> pro)"
    ),
) -> None:
    """快速切换模型厂商 + API key + 思考档位。

    用法:
        vulnclaw config model                 # 显示当前
        vulnclaw config model zhipu           # zhipu glm-5.3 + thinking=low + zhipu key
        vulnclaw config model zhipu high      # zhipu glm-5.3 + thinking=high
        vulnclaw config model ds              # deepseek-flash + thinking=low + ds key
        vulnclaw config model ds --deep       # deepseek-v4-pro + thinking=low
        vulnclaw config model ds --deep max   # deepseek-v4-pro + thinking=max
    """
    if name is None:
        llm = _from_main("load_config")().llm
        console.print(f"[bold]当前模型:[/] {llm.provider} / {llm.model}")
        console.print(f"    thinking_disabled: {llm.thinking_disabled}")
        console.print(f"    reasoning_effort: {getattr(llm, 'reasoning_effort', '')}")
        console.print(
            "[dim]切换: vulnclaw config model <zhipu|ds> [low|high|max] [--deep][/]"
        )
        return

    # 解析 provider 和是否 deep
    provider = name.strip().lower()
    if provider not in {"zhipu", "ds"}:
        console.print(f"[!] 未知模型别名: {provider} (支持: zhipu | ds)")
        raise typer.Exit(1)

    # 解析 thinking 档位
    thinking = (level or "low").strip().lower()
    if thinking not in {"low", "high", "max"}:
        console.print(f"[!] thinking 档位必须是 low/high/max, 得到: {thinking}")
        raise typer.Exit(1)

    # 模型映射
    _MODEL_MAP = {
        "zhipu": {
            "shallow": "glm-5.3",
            "deep": "glm-5.3",  # zhipu 只有 glm-5.3, 深浅靠 thinking 档位
            "base_url": "https://open.bigmodel.cn/api/paas/v4",
        },
        "ds": {
            "shallow": "deepseek-flash",
            "deep": "deepseek-v4-pro",
            "base_url": "https://api.deepseek.com/v1",
        },
    }
    m = _MODEL_MAP[provider]
    model = m["deep"] if deep else m["shallow"]

    config = _from_main("load_config")()
    llm = config.llm
    prev_provider = llm.provider
    llm.provider = provider
    llm.model = model
    llm.base_url = m["base_url"]
    # thinking: 档位 low/high/max; zhipu 用 extra_body, deepseek 忽略
    llm.thinking_disabled = False
    llm.reasoning_effort = thinking
    # 切换 API key(从 provider_keys 读, 缺失则保留当前)
    keys = getattr(llm, "provider_keys", {}) or {}
    if provider in keys and keys[provider]:
        llm.api_key = keys[provider]
        # key_pool() 优先用 api_keys 池, 不同步会导致旧厂商 key 继续生效。
        # 换厂商时旧池子全是旧厂商 key, 直接替换; 同厂商重跑则只把目标 key
        # 提到首位, 保住手动配置的多 key 轮换池。
        pool = [k.strip() for k in (llm.api_keys or []) if k and k.strip()]
        new_key = keys[provider].strip()
        if prev_provider != provider or not pool:
            llm.api_keys = [new_key]
        else:
            llm.api_keys = [new_key] + [k for k in pool if k != new_key]
    save_config(config)

    console.print(
        f"[+] 已切换: [bold cyan]{provider}[/] / [bold]{model}[/] "
        f"thinking=[bold]{thinking}[/]"
    )
    console.print(f"    base_url: {llm.base_url}")
    if provider in keys and keys[provider]:
        console.print(f"    api_key: {llm.api_key[:8]}...")
    else:
        console.print(
            f"[yellow]    provider_keys 里没有 {provider} 的 key, 保持当前 api_key. "
            f"用 `vulnclaw config set llm.provider_keys.{provider} <key>` 配置.[/]"
        )


# 鈹€鈹€ Init command 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
