from datetime import datetime

from aioacme._models import Error


class AcmeError(Exception):
    error: Error

    def __init__(self, error: Error) -> None:
        self.error = error
        super().__init__(str(error))


class RateLimitedError(AcmeError):
    """
    Raised on a ``urn:ietf:params:acme:error:rateLimited`` error.

    See :rfc:`8555#section-6.6`.
    """

    retry_after: datetime | None

    def __init__(self, error: Error, *, retry_after: datetime | None = None) -> None:
        super().__init__(error)
        self.retry_after = retry_after
