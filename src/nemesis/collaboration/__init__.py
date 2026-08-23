"""The collaboration plane: what NEMESIS tells humans, and what it refuses to be told.

Optional by construction. NEMESIS investigates, authorizes and seals with nothing behind
this plane, and the default provider writes to a directory rather than a network. See
ADR-0010 for why a collaboration backend is a provider rather than a dependency, and
``docs/architecture/buzz-integration.md`` for the shape of the integration.
"""

from __future__ import annotations
