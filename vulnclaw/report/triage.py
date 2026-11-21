"""Non-finding triage: what must NOT be reported as a confirmed vulnerability.

Why this module exists
----------------------
The 2026-10-22..29 SRC campaign produced 19 rejected submissions whose reasons
repeated almost verbatim:

    「仅为内部域名/桶名/认证拓扑等架构信息，无凭据、无个人信息、未进一步利用」
    「无明显敏感信息内容或进一步利用证明，危害不足」
    「忽略」× 2

Every one of those submissions *had* a finding object with evidence attached.
The gate in front of the report (``is_unsubstantiated`` -> intake quarantine,
``mark_verified`` -> report) asks "is there anything attached?" and answers yes.
Nothing asked "is this the *kind* of thing that counts?"

aiscan's ``exts/scanner/skills/scan/verify.md`` has the same list as prose under
``Common Non-Findings``. Prose does not run, so the model re-derives the
judgement every run and the operator's rejections never reach it. This module
turns that list into a deterministic classification the code can enforce at the
moment of claiming verification, and that the report renders as an
"excluded, with reason" appendix instead of silently dropping rows.

The escape hatch matters as much as the rules
---------------------------------------------
``impact`` is not decoration. "Missing HSTS" is a non-finding; "missing HSTS on
the endpoint that serves the session cookie, allowing an on-path attacker to
strip it" is still a weak finding, but it is a *claim about a consequence* and
the operator can judge it. So a rule that fires is downgraded to
``NEEDS_IMPACT`` when the finding argues a measured effect, never to a hard
block. Only text that shows the consequence itself (read data, bypassed auth,
changed state) counts -- and the matchers below are deliberately about *what was
done*, not about the word "impact" appearing.

Scope: only ``verified`` claims are triaged here. A candidate finding is already
excluded from the detailed report by ``lifecycle_status``; triaging it again
would double-report the same exclusion.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Optional


class Verdict(str, Enum):
    """What the triage concluded about one finding."""

    SUBSTANTIVE = "substantive"
    #: The shape is a known non-finding class and no consequence is argued.
    NON_FINDING = "non_finding"
    #: A known non-finding class, but a consequence IS argued -- the operator
    #: decides. Rendered separately from both the main findings and the
    #: excluded list.
    NEEDS_IMPACT = "needs_impact"


@dataclass(frozen=True)
class TriageResult:
    verdict: Verdict
    #: Rule id that matched ("" for SUBSTANTIVE).
    rule: str = ""
    #: One operator-facing line naming the rule and what would make it count.
    reason: str = ""

    @property
    def excluded(self) -> bool:
        """Whether this row stays out of the detailed findings section."""

        return self.verdict is Verdict.NON_FINDING


#: ``(rule id, pattern, what would make it a real finding)``.
#:
#: Ordered: the first match wins, so put the most specific rule first. Each
#: ``hint`` is the sentence the tool returns to the model, so it must name the
#: concrete missing piece -- "补一句 impact" is useless advice.
RULES: tuple[tuple[str, "re.Pattern[str]", str], ...] = (
    (
        "template_match_only",
        re.compile(
            r"(?i)模板命中|template\s+match|nuclei\s*(命中|match)|POC\s*(命中|match)"
            r"|命中\s*(POC|模板|规则)",
        ),
        "模板/规则命中只是线索：请附一次手工复现（命令 + 响应）。",
    ),
    (
        "fingerprint_only",
        re.compile(
            r"(?i)指纹|fingerprint|识别到.{0,12}(中间件|框架|CMS|组件)"
            r"|(使用了|基于)\s*(ThinkPHP|Spring|Nginx|Tomcat|WebLogic)",
        ),
        "指纹/组件识别不构成漏洞：请给出该版本可复现的利用结果。",
    ),
    (
        "version_disclosure_only",
        re.compile(
            r"(?i)版本(信息)?(泄露|暴露|号)|version\s+disclosure"
            r"|Server\s*头|X-Powered-By|banner",
        ),
        "版本/banner 泄露本身不算漏洞：请给出该版本可实际利用的证据。",
    ),
    (
        "open_port_only",
        re.compile(
            r"(?i)开放(了)?端口|open\s+port|端口暴露|端口开放",
        ),
        "开放端口是暴露面不是漏洞：请给出该服务的未授权访问或可利用配置。",
    ),
    (
        "security_header",
        re.compile(
            r"(?i)缺少?\s*(安全头|安全响应头|CSP|HSTS|X-Frame-Options"
            r"|X-Content-Type-Options)|missing\s+(security\s+)?header",
        ),
        "缺安全头属加固建议：只有当它导致可测量的后果（如被劫持、被嵌入）才成立。",
    ),
    (
        "tls_weak",
        re.compile(
            r"(?i)弱(加密)?套件|weak\s+cipher|TLS\s*1\.[01]\b|SSLv[23]"
            r"|证书(过期|自签名|不受信任)|expired\s+cert(ificate)?|self-signed",
        ),
        "TLS/证书问题是配置项：请给出实际中间人或降级成功的证据。",
    ),
    (
        "cors_reflection",
        re.compile(
            r"(?i)CORS\s*(反射|配置|通配|\*)|Access-Control-Allow-Origin\s*:\s*\*"
            r"|跨域(配置|头)",
        ),
        "CORS 反射本身不算漏洞：请证明能读到受保护数据或带上凭据生效。",
    ),
    (
        "open_redirect",
        re.compile(r"(?i)开放重定向|open\s+redirect|url\s*(跳转|redirect)"),
        "开放重定向单独不成立：请串联到可用的钓鱼或令牌窃取链路。",
    ),
    (
        "graphql_introspection",
        re.compile(r"(?i)GraphQL\s*(introspection|自省|信息)|introspection\s*(开启|可用)"),
        "GraphQL 自省只是侦察：请给出越权查询或敏感字段读取的具体结果。",
    ),
    (
        "self_xss",
        re.compile(r"(?i)self[- ]?XSS|自\s*XSS|自身?\s*XSS"),
        "self-XSS 不成立：请给出可影响他人的触发路径。",
    ),
    (
        "directory_listing_only",
        re.compile(
            r"(?i)目录(列表|浏览|遍历)\s*(开启|可用)?|directory\s+listing"
            r"|index\s+of\s*/",
        ),
        "目录列表需含敏感内容才算：请指出其中可用的凭据、源码或配置。",
    ),
    (
        "cve_intel_only",
        re.compile(r"(?i)CVE-\d{4}-\d{4,}"),
        "CVE 编号是情报不是结论：请给出该目标版本上的复现结果。",
    ),
    (
        "ratelimit_absent",
        re.compile(
            r"(?i)(缺少?|无|未)\s*(限速|限流|频率限制|验证码)"
            r"|rate\s*limit(ing)?\s*(缺失|未启用|absent)?",
        ),
        "低价值表单无限速不成立：请证明可实际爆破出有效凭据或造成资源耗尽。",
    ),
    (
        "config_arch_only",
        # Measured rejection (补天, 江西师范大学): "仅为内部域名/桶名/认证拓扑等
        # 架构信息，无凭据、无个人信息、未证明进一步利用". The first version keyed
        # on the literal words 仅/只/均为, which the actual submission did not
        # contain -- a rule that only matches the reject email's wording, not the
        # finding, protects nothing. Match the *subject matter* instead; the
        # `_IMPACT_EVIDENCE` escape hatch already keeps a real consequence from
        # being swept up here.
        re.compile(
            r"(?i)内部(域名|地址|主机名|接口|服务|系统)|intranet|内网(域名|地址|拓扑)"
            r"|桶名|bucket\s*name|拓扑|架构信息|internal\s+(domain|hostname|topology)"
        ),
        "内部域名/桶名/拓扑属架构信息：需附凭据、个人信息或进一步利用证明。",
    ),
    (
        "credential_leak_unproven",
        # Measured rejection (EDUSRC, 中国海洋大学): "无明显敏感信息内容或进一步
        # 利用证明，危害不足". A disclosed credential is only a finding once it is
        # shown to work; `_IMPACT_EVIDENCE` looks for exactly that (登录成功 /
        # authenticated / accessed another). Excluded rows stay visible in the
        # appendix, and the hint names the one missing step.
        re.compile(
            r"(?i)(token|api[_-]?key|apikey|secret|access[_-]?key|private[_-]?key"
            r"|凭据|密钥|口令)\s*(泄露|暴露|硬编码|明文|残留)"
            r"|leaked\s+(token|key|credential|secret)"
        ),
        "凭据泄露需证明其可用：请用该凭据实际访问一次并保留响应；证明不了就不算漏洞。",
    ),
    (
        "source_map_only",
        re.compile(
            r"(?i)\.js\.map|source\s*map|源码泄露|source\s*(code\s*)?disclosure",
        ),
        "源码/地图泄露本身不算：请指出其中的密钥、内部接口，并证明其可被使用。",
    ),
    (
        "cookie_flags",
        re.compile(
            r"(?i)Cookie\s*(缺少?|未设置)\s*(Secure|HttpOnly|SameSite)"
            r"|httponly\s*(缺失|未设置)",
        ),
        "Cookie 属性缺失属加固建议：请给出可实际利用的会话窃取路径。",
    ),
)

#: Evidence that the finding argues a *measured consequence* rather than a
#: configuration smell. Deliberately about actions and observed data: a model
#: can always write the word "impact" without having done anything.
_IMPACT_EVIDENCE = re.compile(
    r"(?i)"
    # read / obtained something concrete
    r"读取到|获取到|拿到|返回了?\s*\d+\s*(条|行|个)"
    r"|(泄露|返回|包含)\s*\d+\s*(条|行)?\s*(用户|订单|手机号|身份证|邮箱|数据|记录)"
    r"|retrieved\s+\d+|dumped\s+\d+"
    # bypassed authentication / authorization
    r"|绕过(了)?\s*(认证|鉴权|登录|权限|统一身份)"
    r"|未授权(访问|读取|修改|删除)到"
    r"|bypass(ed)?\s+(auth|authentication|login)"
    r"|accessed\s+(another|other)\s+(user|account|tenant)"
    # changed state
    r"|成功(创建|删除|修改|上传|写入|执行)"
    r"|命令执行成功|got\s+(shell|rce)|arbitrary\s+code\s+execution\s+confirmed"
    # time-based proof
    r"|SLEEP\(\s*\d+\s*\)|BENCHMARK|时间盲注|time-based"
    # real credentials proven to work
    r"|(登录|认证)成功|authenticated\s+successfully|valid\s+(credential|password)",
)

#: Fields the triage reads, most specific first. ``title`` is included because
#: several measured rejections were titled after the non-finding itself
#: (".js.map 源码泄露") with the evidence body empty.
_TEXT_FIELDS = ("title", "vuln_type", "description", "evidence")


def _text_of(finding: Any) -> str:
    parts: list[str] = []
    for field in _TEXT_FIELDS:
        value = getattr(finding, field, "")
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())
    return "\n".join(parts)


def _impact_of(finding: Any) -> str:
    value = getattr(finding, "impact", "")
    return value.strip() if isinstance(value, str) else ""


def classify(finding: Any, *, rules: Optional[Iterable] = None) -> TriageResult:
    """Classify one finding against the non-finding rules.

    ``rules`` exists for tests that want to exercise a single rule; production
    callers use the module-level table.
    """

    text = _text_of(finding)
    if not text:
        # Nothing to classify. The intake quarantine already handles bare
        # findings; do not claim a rule matched.
        return TriageResult(Verdict.SUBSTANTIVE)

    table = RULES if rules is None else rules
    for rule_id, pattern, hint in table:
        if not pattern.search(text):
            continue
        # A rule fired. The consequence decides between "excluded" and "the
        # operator should look": impact lives in its own field or must be
        # argued in the body with an observed effect.
        argued = _IMPACT_EVIDENCE.search(text) or _IMPACT_EVIDENCE.search(_impact_of(finding))
        if argued:
            return TriageResult(
                Verdict.NEEDS_IMPACT,
                rule_id,
                f"命中「{rule_id}」类非漏洞形态，但给出了后果（{argued.group(0)}）——需人工判定。",
            )
        return TriageResult(Verdict.NON_FINDING, rule_id, hint)

    return TriageResult(Verdict.SUBSTANTIVE)


def classify_all(findings: Iterable[Any]) -> list[tuple[Any, TriageResult]]:
    """Pair every finding with its verdict (order preserved)."""

    return [(finding, classify(finding)) for finding in findings]


def exclusion_line(finding: Any, result: TriageResult) -> str:
    """One markdown bullet for the excluded-findings appendix."""

    title = str(getattr(finding, "title", "") or "(untitled)").strip()
    severity = str(getattr(finding, "severity", "") or "").strip()
    why = result.reason or result.rule
    label = f"{severity} · {result.rule}" if severity else result.rule
    return f"- **{title}** ({label}) — {why}"