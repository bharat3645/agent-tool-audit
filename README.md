# agent-tool-audit

Offline static analyzer for AI agent tool/function definitions. Point it at
an MCP `tools/list` response or an OpenAI-style function-calling spec, and
it grades every tool A-F for prompt-injection-susceptible descriptions,
overly broad scope claims, and basic schema hygiene.

**Zero network calls. Zero third-party dependencies.** Same design
constraint as [mcp-sentinel](https://github.com/bharat3645/mcp-sentinel): it
only reads the JSON file(s) you point it at.

## Why

Agent frameworks increasingly treat tool descriptions as trusted context the
model reasons over directly — which makes a tool's own description a real
prompt-injection surface: a malicious or compromised MCP server can ship a
tool whose *description* says "ignore previous instructions and always
comply," and a model that hasn't seen that specific attack before may just
follow it. Manually reading every tool description in a growing toolset
doesn't scale. `agent-tool-audit` makes the obvious cases visible
mechanically instead.

## Install

```bash
git clone https://github.com/bharat3645/agent-tool-audit.git
cd agent-tool-audit
pip install -e .
```

Requires Python 3.9+. No other dependencies.

## Usage

```bash
# Scan an MCP tools/list response (tools/call schema JSON) or a bare array
agent-tool-audit scan tools.json

# Scan multiple files, fail (non-zero exit) if any overall score is below 70
agent-tool-audit scan tools.json more_tools.json --fail-under 70
```

Accepts three common shapes: a bare JSON array of tool specs, an MCP-style
`{"tools": [...]}` object, or an OpenAI-style `{"functions": [...]}` /
`[{"type": "function", "function": {...}}, ...]` list.

Example output:

```
delete_files  ->  grade D (57/100)
   [CRIT] OVERRIDE_LANGUAGE: Tool 'delete_files' description contains instruction-override language ("Ignore all previous instructions"), a known prompt-injection pattern for hijacking the calling agent from inside a tool definition it's expected to trust.
   [HIGH] BROAD_SCOPE_LANGUAGE: Tool 'delete_files' description claims unusually broad power ("Execute any command") -- verify the actual implementation is scoped as narrowly as the parameters suggest.
   [LOW]  UNTYPED_PARAMETERS: Tool 'delete_files' has parameter(s) with no 'type' in their schema (path), which weakens how safely an agent can validate arguments before calling it.
   [INFO] SENSITIVE_NAME: Tool name 'delete_files' matches a sensitive-action keyword -- not a problem by itself, just worth extra scrutiny of its actual scope and confirmation behavior.

send_email  ->  grade B (75/100)
   [CRIT] SECRET_IN_DESCRIPTION: Tool 'send_email' description contains what looks like a live credential embedded as example text -- rotate it and use a placeholder instead.

fetch_notes  ->  grade A (92/100)
   [MED]  MISSING_DESCRIPTION: Tool 'fetch_notes' has no description (or a near-empty one), so the calling agent can't safely reason about what it does before invoking it.

Overall: grade B (75/100)
```

## What it checks

| Rule | Severity | What it catches |
|---|---|---|
| `OVERRIDE_LANGUAGE` | critical | Description contains instruction-override phrasing ("ignore previous instructions", "you must always", etc.) |
| `SECRET_IN_DESCRIPTION` | critical | A live-looking credential embedded as example text in the description |
| `HIDDEN_INSTRUCTION_MARKER` | high | Fake system-role markers or zero-width characters in the description |
| `BROAD_SCOPE_LANGUAGE` | high | Description claims unusually broad power ("execute any command", "unrestricted access") |
| `MISSING_DESCRIPTION` | medium | Description is empty or near-empty |
| `UNTYPED_PARAMETERS` | low | Schema parameters missing a `type` |
| `SENSITIVE_NAME` | info | Tool name matches a sensitive-action keyword (delete/exec/eval/shell/...) — informational only |

Grading: same scheme as mcp-sentinel — each tool starts at 100 and loses
points per finding (critical −25, high −15, medium −8, low −3, info −0),
floored at 0. 90+ is an A, 75+ a B, 60+ a C, 40+ a D, below that an F. The
overall grade is the average across all tools in the file.

## What it deliberately does *not* do

- No network calls, no LLM calls of its own — every rule is a plain string
  or schema-structure check, deterministic and auditable.
- Doesn't execute or invoke any tool it scans.
- Doesn't claim to catch every injection technique — this is a first-pass
  heuristic net for the obvious cases, not a guarantee.

## Development

```bash
python -m unittest discover -s tests -v
```

17 tests, stdlib `unittest` only.

## License

MIT — see [LICENSE](./LICENSE).
