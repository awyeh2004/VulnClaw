"""The non-finding criteria, pinned against the rejections that produced them.

Baseline: the 2026-10-22..29 SRC campaign, 19 submissions, 5 rejections (the
rest were never submitted). The rejection reasons repeated almost verbatim --
「仅为架构信息」「无进一步利用证明」「危害不足」-- and every rejected item had
evidence attached, so the evidence gate had nothing to say about it.

Two directions are tested, and both matter:

- The measured rejections must classify as NON_FINDING (otherwise the criteria
  do not encode what the operators actually rejected).
- Genuine findings with a demonstrated consequence must classify as
  SUBSTANTIVE or NEEDS_IMPACT (otherwise the criteria would suppress real work
  -- the failure mode that costs more than a rejected submission).
"""

from __future__ import annotations

import pytest

from vulnclaw.config.domain_models import VulnerabilityFinding
from vulnclaw.report.triage import (
    RULES,
    Verdict,
    classify,
    exclusion_line,
)


def find(**kwargs) -> VulnerabilityFinding:
    """Build a finding without tripping the intake quarantine unexpectedly."""

    kwargs.setdefault("remediation", "see rule hint")
    return VulnerabilityFinding(**kwargs)


class TestMeasuredRejections:
    """The five real rejections, verbatim in shape."""

    def test_jiangxi_normal_university_config_leak(self):
        # 补天驳回：「仅为内部域名/桶名/认证拓扑等架构信息，无凭据、无个人信息」
        finding = find(
            title="authx-service/configUrl.json 配置文件泄露",
            vuln_type="配置错误",
            description="接口返回内部认证服务拓扑，包含内部域名与桶名",
            evidence="GET /authx-service/configUrl.json -> 200, 包含 auth.xxx.internal",
        )
        result = classify(finding)
        assert result.verdict is Verdict.NON_FINDING
        assert result.rule == "config_arch_only"

    def test_zhongjiao_source_map(self):
        # 补天驳回：同上
        finding = find(
            title="app.99499624.js.map 源码泄露",
            vuln_type="配置错误",
            description="暴露前端 source map",
            evidence="GET /static/app.99499624.js.map -> 200",
        )
        result = classify(finding)
        assert result.verdict is Verdict.NON_FINDING
        assert result.rule == "source_map_only"

    def test_ocean_university_token_leak(self):
        # EDUSRC 驳回：「无明显敏感信息内容或进一步利用证明，危害不足」
        finding = find(
            title="opac 页面 Coze token 泄露",
            vuln_type="配置错误",
            description="前端 JS 中存在 Coze 平台 token",
            evidence="app.js 中发现 token=pat_xxx",
        )
        result = classify(finding)
        # The shape is a source disclosure; without a use it stays excluded.
        assert result.verdict is Verdict.NON_FINDING

    def test_version_disclosure(self):
        finding = find(
            title="服务器版本信息泄露",
            vuln_type="版本信息",
            description="响应头暴露 Nginx 版本",
            evidence="Server: nginx/1.18.0",
        )
        result = classify(finding)
        assert result.verdict is Verdict.NON_FINDING
        assert result.rule == "version_disclosure_only"

    def test_missing_security_headers(self):
        finding = find(
            title="缺少 HSTS 与 CSP 安全头",
            vuln_type="配置错误",
            evidence="响应缺少 Strict-Transport-Security 与 Content-Security-Policy",
        )
        assert classify(finding).verdict is Verdict.NON_FINDING

    def test_cve_number_without_reproduction(self):
        finding = find(
            title="存在 CVE-2024-1086 漏洞",
            vuln_type="已知CVE漏洞",
            evidence="扫描器报告 nf_tables CVE-2024-1086 受影响版本区间",
        )
        assert classify(finding).verdict is Verdict.NON_FINDING

    def test_directory_listing_without_sensitive_content(self):
        finding = find(
            title="目录列表开启",
            vuln_type="敏感目录/文件发现",
            evidence="GET /static/ -> 200, index of /static/",
        )
        assert classify(finding).verdict is Verdict.NON_FINDING


class TestGenuineFindingsSurvive:
    """The reverse direction: real work must not be suppressed."""

    def test_cas_auth_bypass_is_substantive(self):
        # 山东大学 bkjx content.jsp — the one accepted submission.
        finding = find(
            title="bkjx content.jsp 绕过 CAS 统一身份认证",
            vuln_type="认证绕过",
            description="未携带 CAS ticket 直接访问 content.jsp 获取受限页面内容",
            evidence="GET /bkjx/content.jsp -> 200 且返回登录后才可见的课程数据",
            impact="未授权读取任意课程内容",
        )
        assert classify(finding).verdict is Verdict.SUBSTANTIVE

    def test_hackerone_error_body_leak_is_substantive(self):
        # Case 1 in docs/research/real-vuln-cases.md: $15,000.
        finding = find(
            title="reference.json 错误响应体泄露私有报告标题",
            vuln_type="数据泄露",
            description="422 拒绝响应中 context.subject 字段携带私有报告信息",
            evidence="POST /reports/1234/reference.json -> 422, context.subject 返回了报告标题",
            impact="任意 VDP 账号可读取任意私有报告的元数据",
        )
        assert classify(finding).verdict is Verdict.SUBSTANTIVE

    def test_sql_injection_with_extraction_is_substantive(self):
        finding = find(
            title="登录接口 SQL 注入",
            vuln_type="SQL注入",
            evidence="id=1' 返回 SQL 语法错误；UNION 注入读取到 200 条用户记录",
            impact="全库用户数据可读",
        )
        assert classify(finding).verdict is Verdict.SUBSTANTIVE


class TestImpactEscapeHatch:
    """A non-finding shape with a demonstrated consequence is not excluded."""

    def test_version_disclosure_with_exploit_is_needs_impact(self):
        finding = find(
            title="ThinkPHP 版本泄露",
            vuln_type="版本信息",
            evidence="Server: ThinkPHP/5.0.23；随后命令执行成功，whoami 返回 www-data",
            impact="该版本 RCE 已实际打通",
        )
        result = classify(finding)
        assert result.verdict is Verdict.NEEDS_IMPACT
        assert result.rule == "version_disclosure_only"
        assert "需人工" in result.reason

    def test_open_redirect_alone_vs_chained(self):
        alone = find(
            title="开放重定向",
            vuln_type="配置错误",
            evidence="?next=//evil.com 返回 302 到 evil.com",
        )
        assert classify(alone).verdict is Verdict.NON_FINDING

        chained = find(
            title="开放重定向导致 OAuth token 窃取",
            vuln_type="配置错误",
            evidence="?next=//evil.com 携带 code 参数跳转，攻击者可换取 token 并登录成功",
            impact="可劫持任意用户会话",
        )
        assert classify(chained).verdict is Verdict.NEEDS_IMPACT

    def test_impact_field_alone_does_not_excuse(self):
        # Writing "影响很大" in impact is not a demonstrated consequence.
        finding = find(
            title="缺少 HSTS",
            vuln_type="配置错误",
            impact="影响较大，存在被攻击风险",
        )
        assert classify(finding).verdict is Verdict.NON_FINDING

    def test_self_xss_stays_excluded(self):
        finding = find(
            title="搜索框 self-XSS",
            vuln_type="XSS跨站脚本",
            evidence="输入 <script>alert(1)</script> 在自身浏览器执行",
        )
        assert classify(finding).verdict is Verdict.NON_FINDING


class TestRuleTableHygiene:
    def test_rule_ids_unique(self):
        ids = [rule[0] for rule in RULES]
        assert len(ids) == len(set(ids))

    def test_every_hint_names_a_concrete_missing_piece(self):
        # "补一句 impact" would be useless advice; every hint must point at
        # something the model can actually go do.
        for rule_id, _pattern, hint in RULES:
            assert len(hint) >= 10, rule_id
            assert hint.strip().endswith(("。", ".", "）")), rule_id

    def test_empty_finding_is_not_claimed_as_a_match(self):
        result = classify(find(title=""))
        assert result.verdict is Verdict.SUBSTANTIVE
        assert result.rule == ""

    def test_exclusion_line_is_auditable(self):
        finding = find(
            title="缺少 HSTS",
            severity="Low",
            vuln_type="配置错误",
        )
        line = exclusion_line(finding, classify(finding))
        # Title, rule id and reason all present -> a reader can argue with it.
        assert "缺少 HSTS" in line
        assert "security_header" in line
        assert "Low" in line


class TestReportIntegration:
    """The generator must move excluded rows out of the findings section."""

    def _session_with(self, findings):
        from vulnclaw.agent.context import SessionState

        session = SessionState(target="https://example.com")
        # ``add_finding`` rather than a bare list append: get_verified_findings
        # reads the private store that this method keeps in sync.
        for finding in findings:
            session.add_finding(finding)
        return session

    def test_excluded_rows_leave_findings_and_gain_appendix(self, tmp_path):
        from vulnclaw.report.generator import generate_report

        excluded = find(
            title="服务器版本信息泄露",
            severity="Info",
            vuln_type="版本信息",
            evidence="Server: nginx/1.18.0",
            verified=True,
            verification_status="verified",
        )
        real = find(
            title="登录接口 SQL 注入",
            severity="High",
            vuln_type="SQL注入",
            evidence="UNION 注入读取到 200 条用户记录",
            impact="全库数据可读",
            verified=True,
            verification_status="verified",
        )
        session = self._session_with([excluded, real])
        path = generate_report(session, output_path=str(tmp_path / "r.md"))
        text = path.read_text(encoding="utf-8")

        assert "登录接口 SQL 注入" in text
        assert "已排除项" in text or "Excluded" in text
        # The excluded row is present but on the appendix, named with its rule.
        assert "version_disclosure_only" in text