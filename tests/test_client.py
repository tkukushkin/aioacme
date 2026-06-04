from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ec

import aioacme

_DIRECTORY_URL = 'https://acme.test/dir'
_NEW_NONCE_URL = 'https://acme.test/new-nonce'
_NEW_ORDER_URL = 'https://acme.test/new-order'
_DIRECTORY = {
    'newAccount': 'https://acme.test/new-account',
    'newNonce': _NEW_NONCE_URL,
    'newOrder': _NEW_ORDER_URL,
    'revokeCert': 'https://acme.test/revoke-cert',
    'keyChange': 'https://acme.test/key-change',
}
_IDENTIFIERS = [aioacme.Identifier('example.com')]


@pytest.fixture
async def client():
    account_key = ec.generate_private_key(ec.SECP256R1())
    async with aioacme.Client(
        account_key=account_key, directory_url=_DIRECTORY_URL, account_uri='https://acme.test/acct/1'
    ) as client:
        yield client


@pytest.fixture
def acme_mock():
    with respx.mock(assert_all_called=False) as mock:
        mock.get(_DIRECTORY_URL).respond(json=_DIRECTORY)
        mock.head(_NEW_NONCE_URL).respond(headers={'Replay-Nonce': 'nonce'})
        yield mock


async def test_new_order__rate_limited__raises_rate_limited_error_with_retry_after(client, acme_mock):
    acme_mock.post(_NEW_ORDER_URL).respond(
        status_code=429,
        headers={'Replay-Nonce': 'next', 'Retry-After': '120'},
        json={'type': 'urn:ietf:params:acme:error:rateLimited', 'detail': 'too many certificates'},
    )

    with pytest.raises(aioacme.RateLimitedError) as exc_info:
        await client.new_order(_IDENTIFIERS)

    exc = exc_info.value
    assert isinstance(exc, aioacme.AcmeError)
    assert exc.error == aioacme.Error(type='urn:ietf:params:acme:error:rateLimited', detail='too many certificates')
    expected = datetime.now(timezone.utc) + timedelta(seconds=120)
    assert exc.retry_after is not None
    assert abs((exc.retry_after - expected).total_seconds()) < 5


async def test_new_order__rate_limited_without_retry_after_header__retry_after_is_none(client, acme_mock):
    acme_mock.post(_NEW_ORDER_URL).respond(
        status_code=429,
        headers={'Replay-Nonce': 'next'},
        json={'type': 'urn:ietf:params:acme:error:rateLimited', 'detail': 'too many'},
    )

    with pytest.raises(aioacme.RateLimitedError) as exc_info:
        await client.new_order(_IDENTIFIERS)

    assert exc_info.value.retry_after is None


async def test_new_order__other_error__raises_plain_acme_error(client, acme_mock):
    acme_mock.post(_NEW_ORDER_URL).respond(
        status_code=400,
        headers={'Replay-Nonce': 'next'},
        json={'type': 'urn:ietf:params:acme:error:malformed', 'detail': 'bad request'},
    )

    with pytest.raises(aioacme.AcmeError) as exc_info:
        await client.new_order(_IDENTIFIERS)

    assert not isinstance(exc_info.value, aioacme.RateLimitedError)
    assert exc_info.value.error.type == 'urn:ietf:params:acme:error:malformed'


async def test_new_order__bad_nonce__retries_request(client, acme_mock):
    route = acme_mock.post(_NEW_ORDER_URL).mock(
        side_effect=[
            httpx.Response(
                400,
                headers={'Replay-Nonce': 'next'},
                json={'type': 'urn:ietf:params:acme:error:badNonce', 'detail': 'bad nonce'},
            ),
            httpx.Response(
                201,
                headers={'Replay-Nonce': 'next', 'Location': 'https://acme.test/my-order/1'},
                json={
                    'status': 'pending',
                    'identifiers': [{'type': 'dns', 'value': 'example.com'}],
                    'authorizations': ['https://acme.test/authz/1'],
                    'finalize': 'https://acme.test/finalize/1',
                },
            ),
        ]
    )

    order = await client.new_order(_IDENTIFIERS)

    assert order.uri == 'https://acme.test/my-order/1'
    assert route.call_count == 2
