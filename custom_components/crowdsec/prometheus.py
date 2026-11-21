"""Parser für das Prometheus-Textformat – bewusst ohne Home-Assistant-Abhängigkeit.

Unterstützt genau das, was CrowdSec unter ``/metrics`` ausgibt: Kommentare,
Namen mit optionalen Labels (inklusive Escapes in den Werten) und einen Wert,
optional gefolgt von einem Zeitstempel. Unlesbare Zeilen werden übersprungen.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

_NAME = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
_LABEL = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")
_ESCAPES = {"\\": "\\", '"': '"', "n": "\n"}


@dataclass(frozen=True, slots=True)
class Sample:
    name: str
    labels: dict[str, str]
    value: float


def _parse_labels(line: str, pos: int) -> tuple[dict[str, str], int] | None:
    """Liest ``key="value",...}`` ab ``pos``; liefert Labels und die Position nach ``}``."""
    labels: dict[str, str] = {}
    length = len(line)
    while True:
        while pos < length and line[pos] in " ,":
            pos += 1
        if pos >= length:
            return None
        if line[pos] == "}":
            return labels, pos + 1
        match = _LABEL.match(line, pos)
        if not match:
            return None
        key = match.group(0)
        pos = match.end()
        if line[pos : pos + 2] != '="':
            return None
        pos += 2
        value: list[str] = []
        while pos < length and line[pos] != '"':
            char = line[pos]
            if char == "\\" and pos + 1 < length:
                value.append(_ESCAPES.get(line[pos + 1], line[pos + 1]))
                pos += 2
                continue
            value.append(char)
            pos += 1
        if pos >= length:
            return None
        labels[key] = "".join(value)
        pos += 1


def parse(text: str) -> list[Sample]:
    samples: list[Sample] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _NAME.match(line)
        if not match:
            continue
        name = match.group(0)
        pos = match.end()
        labels: dict[str, str] = {}
        if pos < len(line) and line[pos] == "{":
            parsed = _parse_labels(line, pos + 1)
            if parsed is None:
                continue
            labels, pos = parsed
        rest = line[pos:].split()
        if not rest:
            continue
        try:
            value = float(rest[0])
        except ValueError:
            continue
        samples.append(Sample(name, labels, value))
    return samples
