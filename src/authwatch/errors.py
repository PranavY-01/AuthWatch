"""Exception hierarchy. Each class carries the process exit code it maps to."""


class AuthWatchError(Exception):
    """Base class for expected failures; ``exit_code`` decides the process exit status."""

    exit_code = 4

    def __init__(self, message: str, exit_code: int | None = None) -> None:
        super().__init__(message)
        if exit_code is not None:
            self.exit_code = exit_code


class ConfigError(AuthWatchError):
    """Invalid arguments, configuration or output path (exit 2)."""

    exit_code = 2


class InputUnusableError(AuthWatchError):
    """The input as a whole cannot be analyzed, e.g. UTF-16 or binary data (exit 3)."""

    exit_code = 3


class OperationalError(AuthWatchError):
    """The OS refused a read or write (exit 4)."""

    exit_code = 4
