import base64
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime


def b64_encode(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b'=')


def parse_retry_after(value: str | None, *, now: datetime) -> datetime | None:
    """
    Parse the value of a ``Retry-After`` HTTP header into an absolute datetime.

    Per :rfc:`7231#section-7.1.3` the value is either a number of seconds to wait
    (``delay-seconds``) or an ``HTTP-date``. Returns ``None`` if the value is empty
    or can not be parsed.

    :param value: raw header value.
    :param now: reference time used to resolve ``delay-seconds`` values.
    """
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return now + timedelta(seconds=int(value))
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
