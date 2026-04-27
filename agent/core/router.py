from agent.core.config import Config, ModelConfig, build_client, chat

FAST_TASKS = {"recon", "parse", "enumerate"}
SMART_TASKS = {"analyze", "exploit", "report", "plan"}


class ModelRouter:
    """
    Routes LLM calls to the correct model based on task type.

    multi-model:
      fast  (recon/parse/enumerate) → cheap/local model
      smart (analyze/exploit/report/plan) → capable model

    single-model: all tasks go to the primary configured model.
    """

    def __init__(self, cfg: Config):
        self._cfg = cfg
        self._fast_client  = None
        self._smart_client = None

        if cfg.workflow == "multi":
            if cfg.fast_model:
                self._fast_client = build_client(cfg.fast_model)
            if cfg.smart_model:
                self._smart_client = build_client(cfg.smart_model)

        # single-model fallback client (built lazily)
        self._single_client = None

    def _get_single_client(self):
        if self._single_client is None:
            self._single_client = build_client(self._cfg)
        return self._single_client

    def route(self, task_type: str) -> tuple:
        """Return (client, model_config) for the given task type."""
        if self._cfg.workflow == "multi":
            if task_type in FAST_TASKS and self._fast_client:
                return self._fast_client, self._cfg.fast_model
            if task_type in SMART_TASKS and self._smart_client:
                return self._smart_client, self._cfg.smart_model

        return self._get_single_client(), self._cfg

    def chat(self, task_type: str, system: str, messages: list, max_tokens: int = 4096) -> str:
        """Convenience wrapper: route + chat in one call."""
        client, model_cfg = self.route(task_type)
        return chat(client, model_cfg, system, messages, max_tokens)

    @property
    def mode_label(self) -> str:
        """Human-readable label for the startup banner."""
        if self._cfg.workflow == "multi":
            fast_name  = f"{self._cfg.fast_model.model}"  if self._cfg.fast_model  else "?"
            smart_name = f"{self._cfg.smart_model.model}" if self._cfg.smart_model else "?"
            return f"multi-model  fast=[{fast_name}]  smart=[{smart_name}]"
        return f"single  model={self._cfg.model}"
