import os
from dataclasses import dataclass
from pathlib import Path

import yaml

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config.yaml"


@dataclass
class Config:
    provider: str        # anthropic | openai | ollama
    api_key: str
    model: str
    base_url: str | None  # only used by ollama / custom openai endpoints
    nmap_timeout: int
    gobuster_timeout: int
    gobuster_wordlist: str


def load_config() -> Config:
    raw = {}
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r") as f:
            raw = yaml.safe_load(f) or {}

    provider = raw.get("provider", "anthropic").lower()
    block = raw.get(provider, {})
    tools = raw.get("tools", {})

    # api key: config file → env var fallback
    api_key = block.get("api_key", "").strip()
    if not api_key:
        env_map = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai":    "OPENAI_API_KEY",
            "ollama":    "OPENAI_API_KEY",
        }
        api_key = os.getenv(env_map.get(provider, "ANTHROPIC_API_KEY"), "")

    model    = block.get("model", "claude-opus-4-6")
    base_url = block.get("base_url", None)

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
    )


def build_client(config: Config):
    """Return an API client for the configured provider."""
    if config.provider == "anthropic":
        import anthropic
        return anthropic.Anthropic(api_key=config.api_key)

    elif config.provider in ("openai", "ollama"):
        import openai
        kwargs = {"api_key": config.api_key}
        if config.base_url:
            kwargs["base_url"] = config.base_url
        return openai.OpenAI(**kwargs)

    raise ValueError(f"Unsupported provider: {config.provider!r}. Choose anthropic, openai, or ollama.")


def chat(client, config: Config, system: str, messages: list, max_tokens: int = 4096) -> str:
    """Unified chat call — works across all providers."""
    if config.provider == "anthropic":
        response = client.messages.create(
            model=config.model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        )
        return response.content[0].text

    elif config.provider in ("openai", "ollama"):
        full_messages = [{"role": "system", "content": system}] + messages
        response = client.chat.completions.create(
            model=config.model,
            max_tokens=max_tokens,
            messages=full_messages,
        )
        return response.choices[0].message.content

    raise ValueError(f"Unsupported provider: {config.provider!r}")
