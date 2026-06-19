"""Shared CLI context for ClawStrike command handlers.

`CliContext` is the single object threaded through every command handler and
through the tool dispatcher. It replaces the module-level globals that used to
live in loop.py (``current_session``, ``scope``, ``cfg``), so handlers split
across ``agent/core/commands/`` can read and mutate shared state without
importing ``loop`` (which would create a circular import).

This module deliberately imports only leaf modules (config, scope, session,
model_router) — none of which import ``context`` — so it stays cycle-free.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console

from agent.core.config import Config
from agent.core.scope import ScopeManager
from agent.core.session import EngagementSession
from agent.core.model_router import ModelRouter


@dataclass
class CliContext:
    """Mutable shared state for an interactive ClawStrike session.

    Attributes:
        console:   Shared rich Console used for all terminal output.
        cfg:       Loaded configuration (workflow + model settings).
        scope:     ScopeManager enforcing engagement scope on every target.
        router:    ModelRouter used for all LLM calls.
        available: Map of tool-name -> installed?(bool), refreshed by the
                   ``tools`` command. Defaults to an empty dict (treated as
                   "assume available" by the dispatcher).
        session:   The active EngagementSession, or None before a pentest runs.
                   Set by the ``pentest`` handler; read by exploit/loot/report.
        history:   Conversation history passed to the model on each turn.
    """

    console: Console
    cfg: Config
    scope: ScopeManager
    router: ModelRouter
    available: dict = field(default_factory=dict)
    session: Optional[EngagementSession] = None
    history: list = field(default_factory=list)
