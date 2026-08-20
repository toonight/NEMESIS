"""Port definitions: the interfaces every plane talks through.

Protocols only. No implementation, no I/O. Adapters live in their own plane and are
selected at composition time, so swapping a simulated connector for a licensed one
never touches domain or orchestration code.

Trust level: INTERFACE.
"""
