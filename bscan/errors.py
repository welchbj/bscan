"""Custom error types for `bscan`."""


class BscanError(Exception):
    """Base exception type for `bscan` errors."""

    def __init__(self, message, *args):
        self._message = message
        super(BscanError, self).__init__(self._message, *args)

    @property
    def message(self) -> str:
        """Error message to be shown to the end user."""
        return self._message


class BscanInputError(Exception):
    """Exceptions for user-provided input."""


class BscanSubprocessError(Exception):
    """Exceptions related to subprocess spawning/interaction."""
