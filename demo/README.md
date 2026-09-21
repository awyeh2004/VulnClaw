# 应急响应演练靶机

演练靶机**不放在仓库里**，原因见下。

---

## ⚠️ 为什么不放仓库

**实测发现的方法论污染**：把 drill 放在 `demo/` 下后跑 agent，它在报告里引用了
`Dockerfile` 和 `setup.ps1` 作为证据 —— 因为 `shell_command` 的默认工作目录是
VulnClaw 的进程 cwd（仓库根），**agent 一 `ls` 就看到答案卡**。

`setup.ps1` 逐条列出了每个痕迹的目标路径与时间戳，等于把答案摆在桌上。

**结论：drill、题面、答案卡必须放在 agent 工作目录之外。**

---

## 靶机在哪

```
D:\ir-drill\
├── BRIEF.txt          题面（含"运行说明"与"不要贴给 agent"的提示）
├── ANSWER-KEY.md      ⚠️ 答案卡 —— 评估时看，别暴露给 agent
├── setup.ps1          一键搭建（幂等，可 -Rebuild）
├── verify.sh          痕迹自检脚本
└── artifacts/         痕迹素材（会被 docker cp 进容器）
```

**两种形态**（都在 `D:\ir-drill`）：

| 形态 | 说明 | 能练什么 |
|---|---|---|
| **Docker 容器** ⭐ 主推 | `ir-drill:1.0` 镜像 + `ir-drill` 容器；agent 用 `docker exec` 取证 | 真实 `ls -al` / `stat` 时间戳 / `find -ctime` / 真实绝对路径 |
| HTTP 靶机（已随本次删除） | 纯 Python HTTP 服务 | 只要 Web 响应体的场景；**证据与容器不同步，别同时开** |

---

## 搭建

```powershell
powershell -ExecutionPolicy Bypass -File D:\ir-drill\setup.ps1 -Rebuild
```

基础镜像 `vulnclaw-pwn:16.04`（复用项目 `pwn_local` 已缓存的，不需要联网）。

---

## 跑

见 `D:\ir-drill\BRIEF.txt` —— 里面有可直接粘贴的 `/incident-response` 提示词，
以及评估要点与复核命令。

要点：**提示里必须明确"禁止读取本仓库目录下的任何文件"**。

---

## 清理

```powershell
docker rm -f ir-drill
docker rmi -f ir-drill:1.0
```

不碰宿主机系统；所有改动都在容器内。

---

## 本轮演练的历史记录（留作评估基线）

`demo/` 下曾有两版 drill，已移出。**最后一次 Docker 版端到端结果**：

| 项 | agent 答案 | 判定 |
|---|---|---|
| 攻击者 IP | `203.0.113.47`（正确排除运维 IP 与 Googlebot） | ✅ |
| 首次入侵时间 | `2026-03-14 09:22:51` | ✅ |
| 漏洞 + 行号 | 扩展名校验缺陷，`upload.php:21`；后门在 38–39 行 | ✅ |
| 持久化 | **两处都找到**（`/var/spool/cron/crontabs/root` + `/etc/cron.d/demo-persistence`） | ✅ |
| 辅助持久化 | UID=0 账号 `sysupdate` | ✅ |
| 清除方案 | 顺序正确（**先拆持久化再删文件**） | ✅ |
| 路径真实性 | 写的是真实路径，**不再脑补 `/var/www/html` 前缀** | ✅ |

> ⚠️ 但那次**有污染**（agent 读了 `setup.ps1`），所以无法区分"取证得来"还是
> "抄答案得来"。**移出仓库后的重跑才是干净的评估基线。**
