"""The binary-safe wire format between an isolated collector and its parent.

`PivotResult.artifacts` contains the exact bytes collected.  Pydantic's JSON mode treats bytes
as UTF-8 by default, which happened to work for ASCII fixtures and fails on an ordinary page in
another encoding.  The worker pipe therefore names its encoding and base64-encodes only the
artifact map; every other field stays the model's own JSON representation.
"""

from __future__ import annotations

import base64
import binascii
from typing import Final

from nemesis.ports.collection import PivotResult

ARTIFACT_ENCODING: Final = "base64"


class CollectionWireError(ValueError):
    """The child returned a result whose binary envelope cannot be trusted."""


def encode_result(result: PivotResult) -> dict[str, object]:
    """Produce a JSON-serializable result without interpreting artifact bytes."""
    payload = result.model_dump(mode="json", exclude={"artifacts"})
    payload["artifacts"] = {
        evidence_id: base64.b64encode(artifact).decode("ascii")
        for evidence_id, artifact in result.artifacts.items()
    }
    return {"artifact_encoding": ARTIFACT_ENCODING, "payload": payload}


def decode_result(value: object) -> PivotResult:
    """Validate and decode one child result, rejecting ambiguous encodings."""
    if not isinstance(value, dict):
        raise CollectionWireError("collector result envelope is not an object")
    if value.get("artifact_encoding") != ARTIFACT_ENCODING:
        raise CollectionWireError("collector result does not declare base64 artifacts")
    payload = value.get("payload")
    if not isinstance(payload, dict):
        raise CollectionWireError("collector result payload is not an object")
    encoded = payload.get("artifacts")
    if not isinstance(encoded, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in encoded.items()
    ):
        raise CollectionWireError("collector artifacts are not a string-to-string mapping")
    try:
        artifacts = {
            evidence_id: base64.b64decode(item, validate=True)
            for evidence_id, item in encoded.items()
        }
    except (binascii.Error, ValueError) as exc:
        raise CollectionWireError("collector returned invalid base64 artifact bytes") from exc
    rebuilt = dict(payload)
    rebuilt["artifacts"] = artifacts
    return PivotResult.model_validate(rebuilt)


__all__ = ["ARTIFACT_ENCODING", "CollectionWireError", "decode_result", "encode_result"]
