"""Load context-keyed payload data from the payloads directory."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


PAYLOAD_ROOT = Path(__file__).resolve().parent.parent / "payloads"


@dataclass(frozen=True)
class Manifest:
    name: str
    description: str
    max_attempts_per_context: int
    contexts: dict[str, bool]


@dataclass(frozen=True)
class PayloadEntry:
    path: Path
    text: str


class PayloadSet:
    def __init__(self, engine: str, root: Path = PAYLOAD_ROOT):
        self.engine = engine
        self.root = root / engine
        self.manifest = self._load_manifest()
        self._cache: dict[object, list[PayloadEntry]] = {}
        self._validate()

    def _load_manifest(self) -> Manifest:
        manifest_path = self.root / "manifest.toml"
        if not manifest_path.is_file():
            raise FileNotFoundError(
                f"{self.engine}: missing manifest at {manifest_path}"
            )
        raw = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        return Manifest(
            name=raw["name"],
            description=raw.get("description", ""),
            max_attempts_per_context=int(
                raw.get("max_attempts_per_context", 8)
            ),
            contexts={
                name: bool(details.get("required", False))
                for name, details in raw.get("contexts", {}).items()
            },
        )

    def _validate(self) -> None:
        from hx.payloads import Context

        known = {context.value for context in Context}
        for context_name in self.manifest.contexts:
            if context_name not in known:
                raise ValueError(
                    f"{self.engine}/manifest.toml: unknown context "
                    f"{context_name!r}"
                )

        for directory in self.root.iterdir():
            if directory.is_dir() and directory.name not in known:
                raise ValueError(
                    f"{self.engine}: unknown context directory "
                    f"{directory.name!r}"
                )

        for context_name, required in self.manifest.contexts.items():
            if required:
                directory = self.root / context_name
                if not directory.is_dir() or not any(directory.glob("*.txt")):
                    raise ValueError(
                        f"{self.engine}: required context {context_name!r} "
                        f"missing or empty at {directory}"
                    )

    def payloads_for(self, ctx) -> list[PayloadEntry]:
        if ctx in self._cache:
            return self._cache[ctx]
        directory = self.root / ctx.value
        if not directory.is_dir():
            self._cache[ctx] = []
            return []

        entries = [
            PayloadEntry(path=path, text=path.read_text(encoding="utf-8"))
            for path in sorted(directory.glob("*.txt"), key=lambda path: path.name)
        ]
        self._cache[ctx] = entries
        return entries

    def ordered_payloads(self, ctx) -> list[str]:
        entries = self.payloads_for(ctx)
        return [
            entry.text.rstrip("\r\n")
            for entry in entries[:self.manifest.max_attempts_per_context]
        ]


_sets: dict[str, PayloadSet] = {}


def get_payload_set(engine: str = "xss") -> PayloadSet:
    if engine not in _sets:
        _sets[engine] = PayloadSet(engine)
    return _sets[engine]
