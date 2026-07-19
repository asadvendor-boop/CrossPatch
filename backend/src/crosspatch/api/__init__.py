"""Authenticated CrossPatch control API.

Import concrete factories from :mod:`crosspatch.api.app`; keeping the package
initializer side-effect free prevents domain/runtime imports from loading the
entire ASGI dependency graph.
"""
