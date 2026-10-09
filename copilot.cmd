@echo off
setlocal

REM Copilot-mode launcher for the 2026-10-11 competition.
REM Details: IR-FIELD-CARD.md section 2 / IR-PROMPTS.md / IR-RUNBOOK.md section 5.
REM Usage:  copilot.cmd             -> REPL in copilot mode
REM         copilot.cmd --version   -> any args are passed through to vulnclaw
REM
REM Three layers, all measured on 2026-10-09 rehearsals:
REM   1) VULNCLAW_REPL_NO_AUTO=1  -> single-turn chat; no AUTO loop, no target mining.
REM   2) VULNCLAW_SAFETY_PERMISSION_MODE=auto_review -> read-only free; python_execute /
REM      shell_command prompt first. DENY them in copilot mode (that layer caught a
REM      python_execute that tried to curl the target itself).
REM   3) optional COPILOT_DENY=<host> -> that host goes into the HARD denylist
REM      (VULNCLAW_SAFETY_DENIED_HOSTS). This is the only layer that also stops `fetch`:
REM      the approval gate does NOT cover fetch/http_probe_batch, and the model still
REM      mines hosts out of the pasted text, so without this a pasted target is
REM      reachable by the agent's own tools (measured: 6 unprompted fetch calls).
REM      The env var REPLACES the list, so tp.qianxin.com is re-appended here -- losing
REM      the scoring-platform blacklist would be much worse than the noise it saves.
REM      Usage:  set COPILOT_DENY=10.20.0.30
REM              copilot.cmd

set VULNCLAW_REPL_NO_AUTO=1
set VULNCLAW_SAFETY_PERMISSION_MODE=auto_review
if defined COPILOT_DENY set VULNCLAW_SAFETY_DENIED_HOSTS=%COPILOT_DENY%,tp.qianxin.com
REM Optional 4th layer: auto-inject prior-run notes into single-turn chat.
REM OFF by default -- measured 2026-10-09: the goal text is fuzzy-matched and pulled in
REM an unrelated BUUCTF misc note (score 0.333). Prefer on-demand lookup_playbook or
REM pasting the one relevant note by hand (see IR-PROMPTS.md section 0.3).
if defined COPILOT_PLAYBOOKS set VULNCLAW_CHAT_PLAYBOOKS=1

echo.
echo [copilot] NO_AUTO=1            : single-turn chat, no target mining
echo [copilot] PERMISSION=auto_review: exec actions prompt -- deny them
if defined COPILOT_DENY echo [copilot] DENY=%COPILOT_DENY%  : hard-blocked for the agent (fetch included)
if not defined COPILOT_DENY echo [copilot] DENY=not set      : set COPILOT_DENY=^<host^> to hard-block the target
echo [copilot] paste rule           : redact IP / URL / domain as ^<target^>
echo [copilot] template must say    : do not call any tool, do not connect to the target
echo [copilot] cmd tip              : never paste a trailing # comment into cmd.exe
echo [copilot] prompt must stay     : vulnclaw Ready^>   (AUTO / a target = not active)
echo.

vulnclaw %*
endlocal
