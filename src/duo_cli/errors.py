"""Error types with intentionally sanitized, user-actionable messages."""


class DuoCliError(Exception):
    """An ordinary runtime/auth/not-found error (exit status 1)."""


class UsageError(DuoCliError):
    """A semantic command-usage error (exit status 2)."""


class AuthenticationError(DuoCliError):
    """The local emulated-device enrollment cannot be used."""


class BusyError(DuoCliError):
    """Another Duo CLI process owns the exclusive local state lock."""


class RequestNotFoundError(DuoCliError):
    """The requested opaque ID is not currently pending."""


class AlreadyHandledError(DuoCliError):
    """The exact request is no longer pending and must not be answered."""


class AmbiguousRequestError(DuoCliError):
    """A server response contains duplicate exact IDs; fail closed."""


class ContextChangedError(DuoCliError):
    """A selected transaction changed between safety reads."""


class VerifiedPushError(DuoCliError):
    """A verified-push code is missing, inconsistent, or unsafe to guess."""


class ProtocolSemanticsError(DuoCliError):
    """The private transaction has no positive, safe approval discriminator."""
