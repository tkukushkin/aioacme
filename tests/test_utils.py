from datetime import datetime, timedelta, timezone

import pytest

from aioacme._utils import parse_retry_after

NOW = datetime(2026, 6, 4, 12, 0, 0, tzinfo=timezone.utc)


def test_parse_retry_after__delay_seconds__returns_now_plus_seconds():
    assert parse_retry_after('120', now=NOW) == NOW + timedelta(seconds=120)


def test_parse_retry_after__delay_seconds_with_whitespace__returns_now_plus_seconds():
    assert parse_retry_after('  35605 ', now=NOW) == NOW + timedelta(seconds=35605)


def test_parse_retry_after__http_date__returns_absolute_datetime():
    result = parse_retry_after('Wed, 21 Oct 2026 07:28:00 GMT', now=NOW)
    assert result == datetime(2026, 10, 21, 7, 28, 0, tzinfo=timezone.utc)


def test_parse_retry_after__none__returns_none():
    assert parse_retry_after(None, now=NOW) is None


def test_parse_retry_after__empty__returns_none():
    assert parse_retry_after('', now=NOW) is None


@pytest.mark.parametrize('value', ['not a date', 'foo 123', '-5'])
def test_parse_retry_after__garbage__returns_none(value):
    assert parse_retry_after(value, now=NOW) is None
