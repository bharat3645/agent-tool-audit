"""agent-tool-audit: offline static analyzer for AI agent tool/function
definitions (MCP tool schemas, OpenAI-style function-calling specs).

Flags patterns associated with prompt-injection-susceptible tool
descriptions, overly broad scope, and missing/weak schema hygiene.
Zero network calls, zero third-party dependencies -- it only reads the
JSON file(s) it's pointed at.
"""

__version__ = "0.1.0"
