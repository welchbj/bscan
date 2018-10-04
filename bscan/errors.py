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


class BscanForceSkipTarget(BscanError):
    """An exception type for forcing a target to be skipped."""


class BscanForceSilentExit(BscanError):
    """An exception type for ending program execution pre-maturely."""


class BscanInternalError(BscanError):
    """An exception type for `bscan` internal errors."""


class BscanConfigError(BscanError):
    """An exception type for configuration errors."""


class BscanSubprocessError(BscanError):
    """An exception type related to subprocess spawning/interaction."""
