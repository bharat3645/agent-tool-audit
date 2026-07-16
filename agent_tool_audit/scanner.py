"""Load a tool-definition file and grade its risk, tool by tool."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .rules import SEVERITY_WEIGHTS, Finding, evaluate_tool


class ConfigError(ValueError):
    """Raised when a file doesn't look like a recognizable tool list."""


@dataclass
class ToolReport:
    name: str
    findings: list[Finding]

    @property
    def score(self) -> int:
        deduction = sum(SEVERITY_WEIGHTS[f.severity] for f in self.findings)
        return max(0, 100 - deduction)

    @property
    def grade(self) -> str:
        return score_to_grade(self.score)


@dataclass
class ScanReport:
    source: str
    tools: list[ToolReport] = field(default_factory=list)

    @property
    def overall_score(self) -> int:
        if not self.tools:
            return 100
        return round(sum(t.score for t in self.tools) / len(self.tools))

    @property
    def overall_grade(self) -> str:
        return score_to_grade(self.overall_score)


def score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def extract_tool_list(data) -> list:
    """Support the shapes tool/function definitions commonly come in:
    a bare list, an MCP tools/list response ({"tools": [...]}), or an
    OpenAI-style {"functions": [...]} / {"tools": [{"function": {...}}]}.
    """
    if isinstance(data, list):
        return [_unwrap(t) for t in data]
    if isinstance(data, dict):
        if isinstance(data.get("tools"), list):
            return [_unwrap(t) for t in data["tools"]]
        if isinstance(data.get("functions"), list):
            return [_unwrap(t) for t in data["functions"]]
    raise ConfigError(
        "Could not find a tool/function list -- expected a JSON array, or an "
        "object with a 'tools' or 'functions' array."
    )


def _unwrap(entry: dict) -> dict:
    """OpenAI chat-completions tool entries nest the real spec under
    'function'; MCP tools/list entries are already flat."""
    if isinstance(entry, dict) and isinstance(entry.get("function"), dict):
        return entry["function"]
    return entry


def load_file(path: Path) -> list:
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Not valid JSON: {exc}") from exc
    return extract_tool_list(data)


def scan_file(path: Path) -> ScanReport:
    tools = load_file(path)
    report = ScanReport(source=str(path))
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name") or "<unnamed>")
        findings = evaluate_tool(tool)
        report.tools.append(ToolReport(name=name, findings=findings))
    return report
