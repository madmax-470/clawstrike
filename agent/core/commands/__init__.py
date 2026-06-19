"""ClawStrike interactive command handlers.

Each module here owns one family of REPL commands extracted from the original
loop.py dispatcher. Every handler takes the shared :class:`~agent.core.context.CliContext`
and the raw command string, and mutates context state in place.
"""
