# TSecBench API 速查

> 驱动开发时对照用。以 `pip install tsec-benchmark` 后的真实签名为准。

## 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/openapi/v1/challenges` | 列题：unique_code / difficulty / is_completed / container_addr / total_score |
| POST | `/openapi/v1/challenges/start?unique_code=<code>` | 开容器 → `container_addr`（**实测是 list**，如 `[<容器IP:端口>]`） |
| GET | `/openapi/v1/challenges/hint?unique_code=<code>` | 提示（按比例扣分，不建议取） |
| POST | `/openapi/v1/challenges/submit` | body `{"unique_code","flag"}`，长度 1-4096 |
| POST | `/openapi/v1/challenges/close?unique_code=<code>` | 释放容器 |

认证：请求头 `BENCHMARK_TOKEN`（UUID）。VPN 预检：`GET <VPN预检地址(内网)>`，响应 `status=="ok"`。

## SDK（tsec-benchmark 0.1.2 实测签名）

```python
from tsec_benchmark import TSecBenchmark
client = TSecBenchmark(base_url=..., token=..., timeout=30.0, auto_check_vpn=True)
client.check_vpn() -> VpnCheckResult(status, client_ip, ok)
client.list_challenges() -> list[Challenge]
client.start_challenge(code) -> StartResult(unique_code, container_addr)
client.submit_flag(code, flag) -> SubmitResult(correct, awarded, cumulative_score, ...)
client.close_challenge(code) -> CloseResult(unique_code, closed)
```

数据类均为 dataclass（`__dataclass_fields__`，非 pydantic model_fields）。

异常：`DuplicateSubmit`(409 幂等) / `InvalidState`(409 超时或状态错) /
`ResourceUnavailable`(503 槽满或网关超时) / `VpnCheckError` / `TaskNotFound` /
`ChallengeNotFound` / `ValidationError` / `TSecConnectionError`。

## 错误码要点

- 409 `invalid_state` "max active challenge instances reached (3)"：容器槽满。
  处理：close 该题遗留容器后重试一次。
- 409 `duplicate`：重复提交，幂等安全，跳过即可。
- 503 `resource_unavailable`：网关偶发 504 也归此类，可重试一次。
- 提交后超时的题再 submit → `invalid_state`：应停止提交。

## CLI 冒烟

```bash
tsec-run --base-url <URL> --token <TOKEN>
```
