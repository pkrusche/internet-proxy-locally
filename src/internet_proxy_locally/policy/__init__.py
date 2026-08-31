"""config.toml in, engine configs out — and read back to check.

Three modules, in the order they run: `config` parses and validates the
allowlist, `render` turns it into each engine's config through the
templates, and `validate` reads the result back the way the engine will.

The last of those is deliberately not the inverse of the second. It parses
the finished file independently, so a template that renders something
subtly wrong is caught by a second opinion rather than by the code that
produced it.
"""

from __future__ import annotations
