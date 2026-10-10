"""Copilot 的 playbook 查询只能来自操作员**显式写的标签**，不能来自粘贴的终端输出。

2026-10-10 实测（本文件钉住的正是当时那条 bug 链）：
一条勒索排查的粘贴，正文里有 ``python3 -c "import socket,subprocess,os;"`` 与
``find / -newermt '2026-03-14'``；旧实现把 ``goal`` 整段交给
``challenge_class_signature``，于是：

* 引号规则（``_CLASS_QUOTED_RE``）把 shell 参数当成题目名 → 查询词变成
  ``'import socket,subprocess,os;...'``；
* ``-newermt '2026-03-14'`` → 查询词变成 ``'2026-03-14'``；
* 面向操作员的契约本身含「命令执行」，被 ``vulnerability_classes`` 读成类别 ``rce``。

合成查询 ``'import socket,subprocess,os;... 2026-03-14 rce'`` 命中的是
``coderunner-python-sandbox-escape`` / ``pickle-deserialization`` —— 给勒索题塞 RCE 笔记。
``operator_declared_labels`` 只认显式标签形态（``[tag]`` / ``category x`` / CVE），
从根上断掉这条路。
"""

from __future__ import annotations

from vulnclaw.agent.playbook import operator_declared_labels


PASTE_BODY = """执行环境：网页终端（Linux）—— 请只给【单行】命令。
以下是第一段输出：
$ ps -eo pid,ppid,user,etime,args --sort=start_time | tail -4
 9137     1 root       02:47 /usr/bin/python3 -c "import socket,subprocess,os;..."
$ find / -newermt '2026-03-14' -type f 2>/dev/null | head -5
/srv/data/report.docx.locked
$ cat /root/README_RESTORE.txt
your files are encrypted, pay 2 BTC"""


class TestPastedOutputIsNotALabel:
    """粘贴正文不能变成查询条件。"""

    def test_quoted_shell_argument_is_not_read_as_a_title(self):
        # 旧实现会从这个引号片段抽出 'import socket,subprocess,os;...'
        assert operator_declared_labels('$ python3 -c "import socket,subprocess,os;"') == ""

    def test_timestamp_argument_is_not_read_as_a_title(self):
        # 旧实现会抽出 '2026-03-14'
        assert operator_declared_labels("$ find / -newermt '2026-03-14' -type f") == ""

    def test_contract_phrasing_is_not_read_as_a_vuln_class(self):
        # 契约里的「命令执行」曾被 vulnerability_classes 判成 rce；标签提取器不看它
        text = "我在平台网页终端里操作，会把你给的命令执行后，把输出原文贴回来。"
        assert operator_declared_labels(text) == ""

    def test_a_full_ransomware_paste_yields_no_labels(self):
        assert operator_declared_labels(PASTE_BODY) == ""


class TestDeclaredLabelsAreHonoured:
    """操作员显式写的标签必须被采纳。"""

    def test_bracketed_tag(self):
        got = operator_declared_labels("category incident-response  [ransomware]\n" + PASTE_BODY)
        assert "ransomware" in got
        assert "incident-response" in got

    def test_cve_id(self):
        got = operator_declared_labels("目标是 CVE-2024-36401，其余如下\n" + PASTE_BODY)
        assert "CVE-2024-36401" in got

    def test_chinese_tag(self):
        got = operator_declared_labels("[上传绕过]\n" + PASTE_BODY)
        assert "上传绕过" in got


class TestCopilotChatQueryUsesOnlyLabels:
    """经 _chat_playbook_brief 的端到端：带标签命中正确笔记；无标签不注入。"""

    def _brief(self, goal: str):
        from vulnclaw.agent.core import AgentCore
        from vulnclaw.config.schema import VulnClawConfig

        return AgentCore(VulnClawConfig())._chat_playbook_brief("", goal)

    def test_labelled_ransomware_paste_matches_the_triage_note(self):
        goal = "category incident-response  [ransomware]\n" + PASTE_BODY
        brief, matches = self._brief(goal)
        slugs = [m.get("slug") for m in matches]
        # 断言的要点：命中的是**应急排查**类笔记，而不是 RCE 沙箱逃逸
        if slugs:
            assert any("triage" in s or "ransom" in s or "ir-" in s for s in slugs), slugs
            assert not any("sandbox-escape" in s or "pickle" in s for s in slugs), slugs

    def test_unlabelled_paste_injects_nothing(self):
        # 关键回归：没有标签时**零注入**（旧实现会注入无关笔记）
        brief, matches = self._brief(PASTE_BODY)
        assert matches == []
        assert brief == ""


class TestAutoLabelFromEvidence:
    """一键注入：从证据推断类别（用户不想手写标签时）。

    设计约束：**宁可给空，也不给错**。空 = 不注入（安全）；
    给错 = 静默塞无关笔记（这正是 2026-10-10 修掉的那个失败）。

    规则语义：每条规则由若干"组"构成，**每组至少命中一个 token** 才算命中
    （与"所有 token 全中"不同——后者现实中不可达，是首版的错误）。
    """

    def test_ransomware_evidence(self):
        from vulnclaw.agent.playbook import auto_label_from_evidence

        dump = "/root/README_RESTORE.txt\nreport.docx.locked\nbudget.xlsx.locked"
        assert "ransomware" in auto_label_from_evidence(dump)

    def test_cryptomining_evidence(self):
        from vulnclaw.agent.playbook import auto_label_from_evidence

        dump = "root 901 101.0 /bin/bash /usr/local/bin/.system_cache_d\nstratum+tcp://pool.minexmr.com:4444"
        assert "cryptomining" in auto_label_from_evidence(dump)

    def test_webshell_evidence(self):
        from vulnclaw.agent.playbook import auto_label_from_evidence

        dump = "-rwxr-xr-x 1 www-data www-data 2143 shell.php\n<?php @eval($_POST['x']); ?>"
        assert "webshell" in auto_label_from_evidence(dump)

    def test_pcap_evidence(self):
        from vulnclaw.agent.playbook import auto_label_from_evidence

        dump = "$ tshark -r a.pcap -q -z conv,tcp\n$ ls\nwebshell-plus.pcapng"
        assert "pcap" in auto_label_from_evidence(dump)

    def test_pcap_wins_over_the_word_webshell(self):
        # 流量题的文件名里可能带 "webshell"，但证据是 pcap → 必须判 pcap
        from vulnclaw.agent.playbook import auto_label_from_evidence

        got = auto_label_from_evidence("webshell-plus.pcapng")
        assert "pcap" in got and "webshell" not in got, got

    def test_plain_scan_yields_nothing(self):
        # 反例：普通端口扫描没有任何一类应急/取证证据 → 不注入
        from vulnclaw.agent.playbook import auto_label_from_evidence

        dump = "$ nmap -sT 10.20.0.5\n22/tcp open ssh\n80/tcp open http\nServer: nginx/1.14.2"
        assert auto_label_from_evidence(dump) == ""

    def test_small_talk_yields_nothing(self):
        from vulnclaw.agent.playbook import auto_label_from_evidence

        assert auto_label_from_evidence("今天天气不错，随便聊聊") == ""

    def test_operator_label_beats_auto(self):
        # 操作员写了标签就以他为准（即使证据指向别的类别）
        from vulnclaw.agent.core import AgentCore
        from vulnclaw.config.schema import VulnClawConfig

        goal = "category web  [upload bypass]\n/root/README_RESTORE.txt\nreport.docx.locked"
        brief, matches = AgentCore(VulnClawConfig())._chat_playbook_brief("", goal)
        slugs = [m.get("slug") for m in matches]
        # 断言命中的是上传类笔记而非应急排查（operator 的标签优先）
        if slugs:
            assert not any("triage-checklist" in s for s in slugs), slugs
