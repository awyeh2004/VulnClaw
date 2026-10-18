"""Digit-leading hostnames must not be parsed as an allowed port.

2026-10-16 measured (8.duxiaoman.com round): the round prompt
"本轮只测 8.duxiaoman.com 这一个域" matched the 只测<port> pattern,
captured "8", and installed ``allowed_ports=[8]`` on the run's
constraints. The hard scope gate then refused every HTTPS request
("Port(s) 443 are outside allowed scope [8]") and the run burned five
turns working around it. Real port phrases and IP targets keep their
previous behaviour.
"""

from vulnclaw.agent.input_analysis import extract_task_constraints


class TestPortParseGuard:
    def test_digit_leading_hostname_is_not_a_port(self):
        c = extract_task_constraints("本轮只测 8.duxiaoman.com 这一个域，其他域只记录不测试")
        assert c.allowed_ports == []

    def test_ip_target_is_not_a_port(self):
        c = extract_task_constraints("只测 10.252.33.247 这个验证靶")
        assert c.allowed_ports == []

    def test_real_port_phrases_still_parse(self):
        assert extract_task_constraints("本轮只测 8080 端口").allowed_ports == [8080]
        assert extract_task_constraints("仅测试 443").allowed_ports == [443]
        assert extract_task_constraints("only test port 8080").allowed_ports == [8080]
