"""Confinement machinery shared by the planes that need it, and owned by none of them.

Placed below every plane by `import-linter`, so the Effects plane and the collection plane
can both use it and it can reach neither. They need opposite policies — Effects must not
reach outward, collection must not reach inward — which is exactly why the policy is a
parameter and the launch is shared.
"""
