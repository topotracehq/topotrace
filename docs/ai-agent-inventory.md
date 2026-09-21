# AI agent inventory

Visibility into which AI CLI tools, IDE agent integrations, and MCP server
configurations are present on a host -- and whether the model-provider API
key env vars they rely on are set. Community edition, Linux hosts only.

## What's collected

- **AI CLI/agent tools** -- presence of common tools in `PATH` and a few
  standard install locations: `claude`, `gh copilot`, `cursor`, `aider`,
  `codex`, `continue`, `cody`, `windsurf`, `ollama`. Name, resolved path,
  and a best-effort version string.
- **MCP server configs** -- server names and the command/args each one
  runs, read from common Linux config locations (`~/.claude.json`,
  `~/.claude/settings.json`, `~/.config/Claude/claude_desktop_config.json`,
  `~/.cursor/mcp.json`, `~/.codeium/**`, and any `mcp.json`/
  `mcp_servers.json` under `~/.config/*`).
- **Model-provider API key presence** -- whether a fixed list of provider
  key env vars (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`,
  `GEMINI_API_KEY`, `AZURE_OPENAI_API_KEY`, `COHERE_API_KEY`,
  `MISTRAL_API_KEY`, `GROQ_API_KEY`, `HUGGINGFACE_API_KEY`,
  `OPENROUTER_API_KEY`) is **set** in shell rc files (`.bashrc`,
  `.profile`, `.zshrc`, `/etc/environment`) or an MCP config's `env`
  block, and whether the file holding it is readable by group or other.

**Secret values are never collected, read past a non-empty check, or
transmitted.** Only the key's name, the file it was found in, and that
file's permissions are recorded.

## Scoring

`internal/aiagentinv` evaluates what the agent found:

- A key found in a **plaintext, group/other-readable file** is **high**.
- An MCP server whose command isn't on a small curated known-expected
  list (`npx`, `uvx`, `node`, `python`, `python3`, `docker`) is **medium**
  -- worth a look, not a verdict.
- A recognized or unrecognized AI CLI tool is **low** -- informational,
  since the tool's mere presence isn't inherently risky.

Findings surface on the host page, in fleet summary counts, and as a
compliance check (`no-risky-ai-agent-findings` and the equivalent
framework-specific checks) the same way risky browser extensions do.

## Scope

This is a **visibility slice only**: what's installed and configured,
and where. There is no approval workflow, no alerting, and no policy
enforcement layer here -- an operator reviews findings the same way they
review any other fact category. Governance (approving specific tools or
MCP servers, alerting on new findings, blocking policy) is a planned
**Commercial** addition layered on top of this visibility data later.

Linux only for now; no screenshots are captured.
