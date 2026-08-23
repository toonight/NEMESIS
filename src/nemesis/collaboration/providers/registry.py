"""Which collaboration backends exist, resolved by name, closed to additions at runtime.

The same shape as :mod:`nemesis.pilot.providers.registry`, and for the same reason. A
registry with a ``register()`` function is a registry any imported module can add to, which
means the set of backends NEMESIS will talk to is decided by whatever happened to be
imported — an import graph is not an authorization decision. This one is a
``MappingProxyType`` built at import, and adding a backend is a commit.

Resolution fails closed: an unrecognised name raises rather than falling back to the local
provider. A deployment that typed ``buzzz`` in its configuration must find out, not
silently run in a mode where nothing it publishes leaves the machine while its logs say
otherwise.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Final

from nemesis.collaboration.base import CollaborationProvider
from nemesis.collaboration.providers.buzz.provider import (
    PROVIDER_NAME as BUZZ,
)
from nemesis.collaboration.providers.buzz.provider import (
    BuzzCollaborationProvider,
)
from nemesis.collaboration.providers.buzz.transport import BuzzTransport, EventSigner
from nemesis.collaboration.providers.local import (
    PROVIDER_NAME as LOCAL,
)
from nemesis.collaboration.providers.local import (
    LocalCollaborationProvider,
)


class UnknownCollaborationProviderError(ValueError):
    """A backend was named that this build does not have."""


PROVIDERS: Mapping[str, str] = MappingProxyType(
    {
        LOCAL: (
            "Append-only JSONL channels on the local filesystem. No network, no credential. "
            "The default, and the mode every test runs in."
        ),
        BUZZ: (
            "A self-hosted Buzz relay, over NIP-01/NIP-29. The wire format is implemented "
            "and tested; the transport and the Nostr signer are injected Protocols that "
            "NEMESIS ships no implementation of, so this provider reaches nothing unless an "
            "operator supplies both (ADR-0010)."
        ),
    }
)
"""Every backend this build knows, and an honest description of what each one can do."""

DEFAULT_PROVIDER: Final = LOCAL


def build_provider(
    name: str,
    *,
    root: Path | str | None = None,
    relay_url: str | None = None,
    transport: BuzzTransport | None = None,
    signer: EventSigner | None = None,
) -> CollaborationProvider:
    """Resolve a backend name to a provider. Fails closed on a name it does not know.

    The keyword arguments are the union of what the backends need, which is honest at two
    entries and would need reconsidering at five. It is preferable here to a config object
    that every caller has to construct correctly, and to ``**kwargs``, which would let a
    misspelled ``relay_ur1`` reach a provider as silence.
    """
    if name not in PROVIDERS:
        raise UnknownCollaborationProviderError(
            f"unknown collaboration provider {name!r}; this build has "
            f"{sorted(PROVIDERS)}. Refusing rather than defaulting: a deployment that "
            "believes it is publishing to a relay and is writing to a directory would have "
            "no way to notice"
        )
    if name == LOCAL:
        if root is None:
            raise ValueError("the local provider needs a root directory")
        return LocalCollaborationProvider(root)
    return BuzzCollaborationProvider(relay_url=relay_url, transport=transport, signer=signer)


__all__ = [
    "DEFAULT_PROVIDER",
    "PROVIDERS",
    "UnknownCollaborationProviderError",
    "build_provider",
]
