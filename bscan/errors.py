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


class BscanForceSilentExit(Exception):
    """An exception type for ending program execution pre-maturely."""


class BscanInternalError(Exception):
    """An exception type for `bscan` internal errors."""


class BscanConfigError(Exception):
    """An exception type for configuration errors."""


class BscanSubprocessError(Exception):
    """An exception type related to subprocess spawning/interaction."""
