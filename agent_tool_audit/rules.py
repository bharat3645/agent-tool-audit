"""Heuristic rules for a single tool/function definition.

Each rule is a plain function: (tool: dict) -> Finding | None. All
rules are string/structure-based only -- no network access, no
execution of anything the tool describes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}

# Phrases that try to hijack the calling agent's behavior from *inside*
# a tool description -- a known prompt-injection vector, since agents
# often treat tool descriptions as trusted context.
_OVERRIDE_PHRASES = [
    r"ignore (all |any )?(previous|prior|the) instructions",
    r"disregard (the )?system prompt",
    r"you must always",
    r"always comply",
    r"do not (tell|inform|mention) the user",
    r"this overrides",
]
_OVERRIDE_RE = re.compile("|".join(_OVERRIDE_PHRASES), re.IGNORECASE)

_HIDDEN_MARKER_RE = re.compile(r"<system>|###\s*instructions|​|‌|‍")

_BROAD_SCOPE_PHRASES = [
    r"execute any command",
    r"run arbitrary code",
    r"full filesystem access",
    r"unrestricted access",
    r"bypass (all )?(safety|security) checks",
]
_BROAD_SCOPE_RE = re.compile("|".join(_BROAD_SCOPE_PHRASES), re.IGNORECASE)

_SENSITIVE_KEYWORDS = {"delete", "exec", "eval", "shell", "rm", "drop", "sudo", "chmod", "format"}

_SECRET_LIKE = re.compile(
    r"(sk-|ghp_|gho_|xox[baprs]-|AKIA|AIza|glpat-)[A-Za-z0-9_\-]{10,}"
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str


def _description(tool: dict) -> str:
    return str(tool.get("description") or "")


def _name(tool: dict) -> str:
    return str(tool.get("name") or "")


def _schema(tool: dict) -> dict:
    return tool.get("parameters") or tool.get("inputSchema") or {}


def rule_override_language(tool: dict) -> Finding | None:
    desc = _description(tool)
    match = _OVERRIDE_RE.search(desc)
    if match:
        return Finding(
            "OVERRIDE_LANGUAGE",
            "critical",
            f"Tool '{_name(tool)}' description contains instruction-override "
            f"language (\"{match.group(0)}\"), a known prompt-injection "
            "pattern for hijacking the calling agent from inside a tool "
            "definition it's expected to trust.",
        )
    return None


def rule_hidden_markers(tool: dict) -> Finding | None:
    desc = _description(tool)
    if _HIDDEN_MARKER_RE.search(desc):
        return Finding(
            "HIDDEN_INSTRUCTION_MARKER",
            "high",
            f"Tool '{_name(tool)}' description contains a fake system-role "
            "marker or zero-width character, often used to smuggle "
            "instructions past a casual review.",
        )
    return None


def rule_broad_scope_language(tool: dict) -> Finding | None:
    desc = _description(tool)
    match = _BROAD_SCOPE_RE.search(desc)
    if match:
        return Finding(
            "BROAD_SCOPE_LANGUAGE",
            "high",
            f"Tool '{_name(tool)}' description claims unusually broad power "
            f"(\"{match.group(0)}\") -- verify the actual implementation is "
            "scoped as narrowly as the parameters suggest.",
        )
    return None


def rule_missing_description(tool: dict) -> Finding | None:
    desc = _description(tool).strip()
    if len(desc) < 10:
        return Finding(
            "MISSING_DESCRIPTION",
            "medium",
            f"Tool '{_name(tool)}' has no description (or a near-empty one), "
            "so the calling agent can't safely reason about what it does "
            "before invoking it.",
        )
    return None


def rule_sensitive_name(tool: dict) -> Finding | None:
    name = _name(tool)
    tokens = [t for t in re.split(r"[^a-zA-Z]+", name.lower()) if t]
    if any(t in _SENSITIVE_KEYWORDS for t in tokens):
        return Finding(
            "SENSITIVE_NAME",
            "info",
            f"Tool name '{name}' matches a sensitive-action keyword -- not "
            "a problem by itself, just worth extra scrutiny of its actual "
            "scope and confirmation behavior.",
        )
    return None


def rule_untyped_parameters(tool: dict) -> Finding | None:
    schema = _schema(tool)
    props = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(props, dict) or not props:
        return None
    untyped = [name for name, spec in props.items() if isinstance(spec, dict) and "type" not in spec]
    if untyped:
        return Finding(
            "UNTYPED_PARAMETERS",
            "low",
            f"Tool '{_name(tool)}' has parameter(s) with no 'type' in their "
            f"schema ({', '.join(untyped)}), which weakens how safely an "
            "agent can validate arguments before calling it.",
        )
    return None


def rule_secret_in_description(tool: dict) -> Finding | None:
    desc = _description(tool)
    match = _SECRET_LIKE.search(desc)
    if match:
        return Finding(
            "SECRET_IN_DESCRIPTION",
            "critical",
            f"Tool '{_name(tool)}' description contains what looks like a "
            "live credential embedded as example text -- rotate it and use "
            "a placeholder instead.",
        )
    return None


ALL_RULES = [
    rule_override_language,
    rule_hidden_markers,
    rule_broad_scope_language,
    rule_missing_description,
    rule_sensitive_name,
    rule_untyped_parameters,
    rule_secret_in_description,
]


def evaluate_tool(tool: dict) -> list[Finding]:
    findings = []
    for rule in ALL_RULES:
        result = rule(tool)
        if result is not None:
            findings.append(result)
    return findings
