"""The analyst surface: a case file, not a dashboard.

Renders one investigation as a self-contained HTML page whose visual hierarchy is inverted —
uncertainty is drawn as physical space and refusals carry more weight than conclusions,
because in this platform the refusal is the product. See :mod:`nemesis.ui.investigation`.
"""

from __future__ import annotations

from nemesis.ui.investigation import render_investigation

__all__ = ["render_investigation"]
