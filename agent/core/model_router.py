from __future__ import annotations

import json
import re
from typing import Optional

from agent.core.config import (
    Config, ModelConfig,
    build_client, chat as _cfg_chat,
    load_config,
)


class ModelRouter:
    """
    Single interface between ClawStrike and any LLM provider.

    Nothing in ClawStrike calls anthropic/openai/ollama directly —
    everything goes through ModelRouter.

    Usage:
        router = ModelRouter.from_config()
        router.fast.chat(messages, system)       # cheap model
        router.smart.call_with_tools(...)        # capable model
    """

    def __init__(self, config) -> None:
        """
        config: a Config or ModelConfig instance from agent.core.config
        """
        self._config = config
        self._client = None          # built lazily by _get_client()
        self._fast_router:  Optional[ModelRouter] = None
        self._smart_router: Optional[ModelRouter] = None

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_config(cls) -> "ModelRouter":
        """Load config.yaml and build a fully wired ModelRouter."""
        cfg = load_config()
        router = cls(cfg)

        if cfg.workflow == "multi":
            if cfg.fast_model:
                router._fast_router = cls(cfg.fast_model)
            if cfg.smart_model:
                router._smart_router = cls(cfg.smart_model)

        return router

    # ── Provider accessors ────────────────────────────────────────────────────

    @property
    def fast(self) -> "ModelRouter":
        """Fast/cheap model — recon, parsing, enumeration."""
        return self._fast_router or self

    @property
    def smart(self) -> "ModelRouter":
        """Smart/capable model — analysis, exploitation planning, reports."""
        return self._smart_router or self

    @property
    def provider(self) -> str:
        return self._config.provider

    @property
    def model_name(self) -> str:
        return self._config.model

    @property
    def mode_label(self) -> str:
        """Human-readable label for the startup banner."""
        cfg = self._config
        if getattr(cfg, "workflow", "single") == "multi":
            fast_name  = cfg.fast_model.model  if cfg.fast_model  else "?"
            smart_name = cfg.smart_model.model if cfg.smart_model else "?"
            return f"multi-model  fast=[{fast_name}]  smart=[{smart_name}]"
        return f"single  model={cfg.model}"

    # ── Client ────────────────────────────────────────────────────────────────

    def _get_client(self):
        if self._client is None:
            self._client = build_client(self._config)
        return self._client

    # ── Chat ─────────────────────────────────────────────────────────────────

    def chat(
        self,
        messages: list,
        system: str = "",
        max_tokens: int = 4096,
    ) -> str:
        """
        Simple chat — returns response text.
        Used for: agent conversation, planning, summary, report writing.
        """
        return _cfg_chat(
            self._get_client(), self._config,
            system, messages, max_tokens,
        )

    # ── Tool use ──────────────────────────────────────────────────────────────

    def call_with_tools(
        self,
        messages: list,
        tools: list,
        system: str = "",
        max_tokens: int = 4096,
    ) -> list:
        """
        Structured tool/function calling.

        tools: Anthropic-format tool definitions
            [{"name": "...", "description": "...", "input_schema": {...}}]

        Returns a provider-agnostic list:
            [{"name": "tool_name", "input": {...}}, ...]

        Dispatches to the correct provider implementation, with a JSON
        fallback for models that don't support native function calling.
        """
        provider = self._config.provider

        if provider == "anthropic":
            return self._anthropic_tools(messages, tools, system, max_tokens)

        if provider in ("openai", "deepseek", "groq", "ollama",
                        "mistral", "clawstrike"):
            return self._openai_tools(messages, tools, system, max_tokens)

        return self._json_fallback(messages, tools, system, max_tokens)

    def _anthropic_tools(
        self, messages: list, tools: list, system: str, max_tokens: int,
    ) -> list:
        client = self._get_client()
        response = client.messages.create(
            model=self._config.model,
            max_tokens=max_tokens,
            tools=tools,
            tool_choice={"type": "auto"},
            system=system,
            messages=messages,
        )
        results = []
        for block in response.content:
            if block.type == "tool_use":
                results.append({"name": block.name, "input": block.input})
        return results

    def _openai_tools(
        self, messages: list, tools: list, system: str, max_tokens: int,
    ) -> list:
        # Convert Anthropic tool format → OpenAI function format
        oai_tools = [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {}),
                },
            }
            for t in tools
        ]

        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.extend(messages)

        client = self._get_client()
        response = client.chat.completions.create(
            model=self._config.model,
            max_tokens=max_tokens,
            tools=oai_tools,
            tool_choice="auto",
            messages=msgs,
        )

        results = []
        tool_calls = response.choices[0].message.tool_calls or []
        for tc in tool_calls:
            try:
                results.append({
                    "name": tc.function.name,
                    "input": json.loads(tc.function.arguments),
                })
            except Exception:
                continue
        return results

    def _json_fallback(
        self, messages: list, tools: list, system: str, max_tokens: int,
    ) -> list:
        """
        For models without native function calling.
        Instructs the model to use <tool_call>name({json})</tool_call> tags.
        ClawStrike-7B is trained to emit this format.
        """
        tool_desc = "\n".join(
            f"Tool: {t['name']}\n"
            f"Call format: <tool_call>{t['name']}({{json}})</tool_call>"
            for t in tools
        )
        augmented = messages.copy()
        augmented[-1] = dict(augmented[-1])
        augmented[-1]["content"] = (
            augmented[-1]["content"]
            + f"\n\nAvailable tools:\n{tool_desc}\n\n"
            "Use <tool_call>tool_name({json})</tool_call> format."
        )

        text = self.chat(augmented, system, max_tokens)

        results = []
        pattern = r"<tool_call>(\w+)\(({.*?})\)</tool_call>"
        for m in re.finditer(pattern, text, re.DOTALL):
            try:
                results.append({
                    "name": m.group(1),
                    "input": json.loads(m.group(2)),
                })
            except Exception:
                continue
        return results

    # ── Legacy compatibility ───────────────────────────────────────────────────
    # loop.py and other callers use router.chat(task_type, system, messages, ...)
    # This shim preserves that interface while the migration happens.

    def legacy_chat(
        self, task_type: str, system: str, messages: list, max_tokens: int = 4096,
    ) -> str:
        """
        Backward-compatible wrapper for router.chat(task_type, system, messages).
        Routes smart tasks to self.smart, fast tasks to self.fast.
        """
        _FAST = {"recon", "parse", "enumerate"}
        if task_type in _FAST:
            return self.fast.chat(messages, system, max_tokens)
        return self.smart.chat(messages, system, max_tokens)
