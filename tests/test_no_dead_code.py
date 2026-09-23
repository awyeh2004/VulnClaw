"""静态卫生闸门：``return`` 之后的死代码。

死代码对行为测试完全隐形——函数存在、名字已登记、被调用路径的行覆盖看起来
正常。真实事故：黑板工具的三个 handler 被粘到另一个（从未被调用的）函数的
``return`` 之后，于是三件对外公布的工具永不执行、静默返回 ``None``。

这个闸门用 AST 扫 ``vulnclaw/`` 包，任何同一代码块里跟在
``return`` / ``raise`` / ``continue`` / ``break`` 之后的语句都判为失败。
"""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "vulnclaw"
TERMINATORS = (ast.Return, ast.Raise, ast.Continue, ast.Break)


def _scan(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    findings: list[str] = []

    def walk(node: ast.AST, func: str) -> None:
        for field in ("body", "orelse", "finalbody"):
            block = getattr(node, field, None)
            if not isinstance(block, list) or not block:
                continue
            for index, stmt in enumerate(block[:-1]):
                if isinstance(stmt, TERMINATORS):
                    after = block[index + 1]
                    findings.append(
                        f"{path.name}:{after.lineno}: unreachable, follows "
                        f"{type(stmt).__name__.lower()} on line {stmt.lineno} in {func}()"
                    )
        for child in ast.iter_child_nodes(node):
            walk(child, func)

    for item in ast.walk(tree):
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            walk(item, item.name)
    return findings


def test_no_unreachable_statements_in_package():
    findings: list[str] = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        findings.extend(_scan(path))
    assert not findings, "dead code after a terminator:\n  " + "\n  ".join(findings)
