from __future__ import annotations


class ToCodeError(Exception):
    """Base class for user-facing exporter failures."""


class BackendError(ToCodeError):
    """Raised when a decompiler backend cannot complete an operation."""


class BackendJsonError(BackendError):
    """Raised when a backend command was expected to return JSON and did not."""
