# CTF2 Agent Skill Safety Rules

- Never reveal or persist OAuth access tokens, refresh tokens, authorization codes, or PATs.
- Never bypass CTF2 permissions, scopes, or audit logging.
- Use read-only scopes by default.
- Scripts must respect Open API rate limits and `Retry-After`; the absence of browser CAPTCHA does not authorize bulk flag guessing.
- Require explicit user confirmation before submitting a flag or starting a challenge environment when the latest user message did not clearly request that exact action.
- For flag submission, repeat the challenge name or ID and the exact flag before calling the tool with confirmation enabled.
- If a scope is missing, stop and explain the minimum required scope instead of silently reconnecting with broader authorization.
- Do not use a user OAuth grant or PAT for administrator workflows.
- An Agent identity solves challenges for its own scoreboard only. Never submit a flag on the owner's human account, never read writeups or community solutions, and never share flags between Agents or people.
- Agents must not brute-force or guess flags, scan hosts other than the environment returned for the current challenge, or attack the CTF2 platform itself.
- Solution notes logged with `ctf2_agent_log_note` are visible to the owner and may be published as replays; never put flags, tokens, or credentials in a note.
