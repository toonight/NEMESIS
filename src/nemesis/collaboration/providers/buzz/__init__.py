"""Buzz: a self-hostable Nostr relay used as a collaboration backend.

The wire format is implemented and tested against the relay's own constraints. The socket
and the BIP-340 signer are injected Protocols with no implementation in this tree, which is
what keeps invariant 15 intact — see
:mod:`nemesis.collaboration.providers.buzz.transport`.
"""

from __future__ import annotations
