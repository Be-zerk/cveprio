"""Settings from environment variables (and an optional ``.env`` file).

Secrets are read here and nowhere else. ``Settings.__repr__`` masks them so they
cannot leak into logs or reports by accident.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURES = PROJECT_ROOT / "fixtures" / "demo"
SECRET_FIELDS = {"nvd_api_key", "llm_api_key", "anthropic_api_key"}


def load_dotenv(path: Path) -> None:
    """Minimal .env loader (KEY=VALUE lines). Existing environment variables win."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass
class Settings:
    nvd_api_key: str | None = None
    llm_provider: str = "none"
    llm_base_url: str = "http://localhost:11434/v1"
    llm_model: str = "qwen2.5:3b"
    llm_api_key: str | None = None
    ollama_url: str = "http://localhost:11434"
    llm_num_ctx_max: int = 16384
    llm_timeout_s: float = 600.0
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-opus-5-5"
    anthropic_fallbacks: bool = True
    cache_path: Path = field(default_factory=lambda: PROJECT_ROOT / ".cache" / "responses.sqlite")

    @classmethod
    def from_env(cls, dotenv: Path | None = None) -> Settings:
        load_dotenv(dotenv or PROJECT_ROOT / ".env")
        env = os.environ.get

        def opt(name: str) -> str | None:
            v = env(name, "").strip()
            return v or None

        return cls(
            nvd_api_key=opt("NVD_API_KEY"),
            llm_provider=(opt("CVEPRIO_LLM_PROVIDER") or "none").lower(),
            llm_base_url=opt("CVEPRIO_LLM_BASE_URL") or cls.llm_base_url,
            llm_model=opt("CVEPRIO_LLM_MODEL") or cls.llm_model,
            llm_api_key=opt("CVEPRIO_LLM_API_KEY"),
            ollama_url=opt("CVEPRIO_OLLAMA_URL") or cls.ollama_url,
            llm_num_ctx_max=int(opt("CVEPRIO_LLM_NUM_CTX_MAX") or cls.llm_num_ctx_max),
            llm_timeout_s=float(opt("CVEPRIO_LLM_TIMEOUT_S") or cls.llm_timeout_s),
            anthropic_api_key=opt("ANTHROPIC_API_KEY"),
            anthropic_model=opt("CVEPRIO_ANTHROPIC_MODEL") or cls.anthropic_model,
            anthropic_fallbacks=(opt("CVEPRIO_ANTHROPIC_FALLBACKS") or "on").lower() not in {"off", "0", "false"},
        )

    def __repr__(self) -> str:
        parts = []
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name in SECRET_FIELDS:
                value = "***set***" if value else None
            parts.append(f"{f.name}={value!r}")
        return "Settings(" + ", ".join(parts) + ")"

    __str__ = __repr__
