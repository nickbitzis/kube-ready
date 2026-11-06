"""Read multi-document YAML files into K8sObjects, keeping the line where each document starts."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import Path

import yaml

from .model import K8sObject

DOC_SEPARATOR = re.compile(r"^---\s*(#.*)?$")
YAML_SUFFIXES = {".yaml", ".yml"}
SKIP_DIRS = {"node_modules", "venv", "__pycache__"}


class LoadError(Exception):
    """A file could not be parsed as YAML."""


def split_documents(text: str) -> Iterator[tuple[int, str]]:
    """Yield (first content line, document text) for each document in a YAML stream."""
    chunks: list[tuple[int, list[str]]] = []
    start, buf = 1, []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if DOC_SEPARATOR.match(line):
            chunks.append((start, buf))
            start, buf = lineno + 1, []
        else:
            buf.append(line)
    chunks.append((start, buf))
    for start, lines in chunks:
        offset = next(
            (i for i, ln in enumerate(lines) if ln.strip() and not ln.lstrip().startswith("#")),
            None,
        )
        if offset is not None:
            yield start + offset, "\n".join(lines)


def parse_text(text: str, path: str = "<memory>") -> list[K8sObject]:
    """Parse YAML text. Documents without kind and apiVersion are skipped, so non-Kubernetes YAML is ignored."""
    objects: list[K8sObject] = []
    for line, chunk in split_documents(text):
        try:
            doc = yaml.safe_load(chunk)
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            where = line + mark.line if mark is not None else line
            raise LoadError(f"{path}:{where}: invalid YAML: {getattr(exc, 'problem', exc)}") from exc
        if not isinstance(doc, dict) or "kind" not in doc or "apiVersion" not in doc:
            continue
        if doc["kind"] == "List":
            for item in doc.get("items") or []:
                if isinstance(item, dict) and "kind" in item:
                    objects.append(K8sObject(item, path, line))
            continue
        objects.append(K8sObject(doc, path, line))
    return objects


def discover(paths: Iterable[str]) -> list[Path]:
    """Expand directories into their YAML files, skipping hidden and vendor folders."""
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                rel_parts = f.relative_to(p).parts
                if any(part.startswith(".") or part in SKIP_DIRS for part in rel_parts[:-1]):
                    continue
                if f.is_file() and f.suffix in YAML_SUFFIXES:
                    files.append(f)
        else:
            files.append(p)
    return files


def load_paths(paths: Iterable[str]) -> tuple[list[K8sObject], list[str]]:
    """Load every file. Returns (objects, list of file paths read)."""
    objects: list[K8sObject] = []
    read: list[str] = []
    for f in discover(paths):
        if not f.exists():
            raise LoadError(f"{f}: no such file or directory")
        objects.extend(parse_text(f.read_text(encoding="utf-8"), f.as_posix()))
        read.append(f.as_posix())
    return objects, read
