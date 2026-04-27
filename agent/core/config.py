import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config.yaml"


@dataclass
class ModelConfig:
    """Holds provider/model settings for one LLM slot (fast or smart)."""
    provider: str
    api_key: str
    model: str
    base_url: Optional[str] = None


@dataclass
class Config:
    provider: str        # anthropic | openai | ollama
    api_key: str
    model: str
    base_url: Optional[str]
    nmap_timeout: int
    gobuster_timeout: int
    gobuster_wordlist: str
    workflow: str = "single"                  # single / multi
    fast_model: Optional[ModelConfig] = None
    smart_model: Optional[ModelConfig] = None


def _resolve_api_key(block: dict, provider: str) -> str:
    key = block.get("api_key", "").strip()
    if not key:
        env_map = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai":    "OPENAI_API_KEY",
            "ollama":    "OPENAI_API_KEY",
            "groq":      "GROQ_API_KEY",
            "deepseek":  "DEEPSEEK_API_KEY",
            "mistral":   "MISTRAL_API_KEY",
        }
        key = os.getenv(env_map.get(provider, "ANTHROPIC_API_KEY"), "")
    return key


def _load_model_block(raw: dict, section: str) -> Optional[ModelConfig]:
    """Parse a fast_model / smart_model block from raw config dict."""
    block = raw.get(section)
    if not block:
        return None
    provider = block.get("provider", "ollama").lower()
    return ModelConfig(
        provider=provider,
        api_key=_resolve_api_key(block, provider),
        model=block.get("model", ""),
        base_url=block.get("base_url") or None,
    )


def load_config() -> Config:
    raw = {}
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r") as f:
            raw = yaml.safe_load(f) or {}

    provider = raw.get("provider", "anthropic").lower()
    block    = raw.get(provider, {})
    tools    = raw.get("tools", {})

    api_key  = _resolve_api_key(block, provider)
    model    = block.get("model", "claude-opus-4-6")
    base_url = block.get("base_url", None)
    workflow = raw.get("workflow", "single").lower()

    return Config(
        provider=provider,
        api_key=api_key,
        model=model,
        base_url=base_url,
        nmap_timeout=int(tools.get("nmap_timeout", 120)),
        gobuster_timeout=int(tools.get("gobuster_timeout", 120)),
        gobuster_wordlist=tools.get(
            "gobuster_wordlist", "/usr/share/wordlists/dirb/common.txt"
        ),
        workflow=workflow,
        fast_model=_load_model_block(raw, "fast_model"),
        smart_model=_load_model_block(raw, "smart_model"),
    )


def build_client(config):
    """Return an API client for the given Config or ModelConfig."""
    provider = config.provider
    api_key  = config.api_key
    base_url = getattr(config, "base_url", None)

    if provider == "anthropic":
        import anthropic
        return anthropic.Anthropic(api_key=api_key)

    elif provider in ("openai", "ollama", "groq", "deepseek", "mistral"):
        import openai
        kwargs = {"api_key": api_key or "none"}
        if base_url:
            kwargs["base_url"] = base_url
        elif provider == "groq":
            kwargs["base_url"] = "https://api.groq.com/openai/v1"
        elif provider == "deepseek":
            kwargs["base_url"] = "https://api.deepseek.com/v1"
        elif provider == "mistral":
            kwargs["base_url"] = "https://api.mistral.ai/v1"
        return openai.OpenAI(**kwargs)

    raise ValueError(f"Unsupported provider: {provider!r}. Choose anthropic, openai, ollama, groq, deepseek, or mistral.")


def chat(client, config, system: str, messages: list, max_tokens: int = 4096) -> str:
    """Unified chat call — works across all providers."""
    provider = config.provider
    model    = config.model

    if provider == "anthropic":
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        )
        return response.content[0].text

    elif provider in ("openai", "ollama", "groq", "deepseek", "mistral"):
        full_messages = [{"role": "system", "content": system}] + messages
        response = client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=full_messages,
        )
        return response.choices[0].message.content

    raise ValueError(f"Unsupported provider: {provider!r}")


def save_workflow_config(workflow: str, fast: Optional[ModelConfig], smart: Optional[ModelConfig]) -> None:
    """Persist workflow + model choices back to config.yaml."""
    raw = {}
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r") as f:
            raw = yaml.safe_load(f) or {}

    raw["workflow"] = workflow

    if fast:
        raw["fast_model"] = {
            "provider": fast.provider,
            "model":    fast.model,
            "api_key":  fast.api_key,
            "base_url": fast.base_url or "",
        }

    if smart:
        raw["smart_model"] = {
            "provider": smart.provider,
            "model":    smart.model,
            "api_key":  smart.api_key,
            "base_url": smart.base_url or "",
        }

    with open(CONFIG_PATH, "w") as f:
        yaml.dump(raw, f, default_flow_style=False, allow_unicode=True)
