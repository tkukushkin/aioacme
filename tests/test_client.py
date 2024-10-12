from datetime import datetime, timedelta, timezone
from unittest import mock

import anyio
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

import aioacme


async def test_get_terms_of_service(client):
    # act
    result = await client.get_terms_of_service()

    # assert
    assert result == 'data:text/plain,Do%20what%20thou%20wilt'


async def test_get_account__not_registered(client):
    # act
    account = await client.get_account()

    # assert
    assert account == aioacme.Account(uri=mock.ANY, status=aioacme.AccountStatus.valid, orders=mock.ANY)


async def test_get_account__already_registered_but_uri_not_provided__return_existing(client):
    # arrange
    account = await client.get_account()

    # act
    async with aioacme.Client(
        account_key=client.account_key, directory_url=client.directory_url, ssl=False
    ) as new_client:
        result = await new_client.get_account()

    # assert
    assert result == account


async def test_get_account__already_registered_and_uri_provided__return_existing(client):
    # arrange
    account = await client.get_account()

    # act
    async with aioacme.Client(
        account_key=client.account_key, directory_url=client.directory_url, ssl=False, account_uri=account.uri
    ) as new_client:
        result = await new_client.get_account()

    # assert
    assert result == account


async def test_update_account__contant(client):
    # act
    account = await client.update_account(contact=['mailto:bar@example.com'])

    # assert
    assert account == aioacme.Account(
        uri=client.account_uri, status=aioacme.AccountStatus.valid, orders=mock.ANY, contact=['mailto:bar@example.com']
    )


async def test_update_account__deactivate(client):
    # act
    account = await client.update_account(status=aioacme.AccountStatus.deactivated)

    # assert
    assert account == aioacme.Account(uri=client.account_uri, status=aioacme.AccountStatus.deactivated, orders=mock.ANY)


async def test_new_order(client, domain, pebble_url):
    # arrange
    identifiers = [aioacme.Identifier(domain)]

    # act
    order = await client.new_order(identifiers)

    # assert
    assert order == aioacme.Order(
        uri=mock.ANY,
        identifiers=identifiers,
        authorizations=[mock.ANY],
        status=aioacme.OrderStatus.pending,
        expires=mock.ANY,
        finalize=mock.ANY,
    )
    assert order.uri.startswith(f'{pebble_url}/my-order')
    assert order.finalize.startswith(f'{pebble_url}/finalize-order')
    assert isinstance(order.expires, datetime)
    assert order.authorizations[0].startswith(f'{pebble_url}/authZ')


async def test_new_order__with_not_before_and_not_after(client, domain, pebble_url):
    # arrange
    identifiers = [aioacme.Identifier(domain)]
    not_before = datetime.now(timezone.utc)
    not_after = not_before + timedelta(days=30)

    # act
    order = await client.new_order(identifiers, not_before=not_before, not_after=not_after)

    # assert
    assert order == aioacme.Order(
        uri=mock.ANY,
        identifiers=identifiers,
        authorizations=[mock.ANY],
        status=aioacme.OrderStatus.pending,
        expires=mock.ANY,
        finalize=mock.ANY,
        not_before=not_before,
        not_after=not_after,
    )
    assert order.uri.startswith(f'{pebble_url}/my-order')
    assert order.finalize.startswith(f'{pebble_url}/finalize-order')
    assert isinstance(order.expires, datetime)
    assert order.authorizations[0].startswith(f'{pebble_url}/authZ')


async def test_get_order__no_order__exception(client, pebble_url):
    # act
    with pytest.raises(aioacme.AcmeError) as exc_info:
        await client.get_order(f'{pebble_url}/my-order/foo')

    assert exc_info.value.error == aioacme.Error(type='unknown', detail='')  # pebble doesn't return a proper error


async def test_get_order__order_exists__ok(client, domain):
    # arrange
    created_order = await client.new_order([aioacme.Identifier(domain)])

    # act
    result = await client.get_order(created_order.uri)

    # assert
    assert result == created_order


async def test_get_authorization(client, domain, pebble_url):
    # arrange
    identifier = aioacme.Identifier(domain)
    order = await client.new_order([identifier])
    authorization_uri = order.authorizations[0]

    # act
    result = await client.get_authorization(authorization_uri)

    # assert
    assert result == aioacme.Authorization(
        uri=authorization_uri,
        identifier=identifier,
        status=aioacme.AuthorizationStatus.pending,
        expires=mock.ANY,
        challenges=mock.ANY,
        wildcard=False,
    )
    assert isinstance(result.expires, datetime)

    challenges = sorted(result.challenges, key=lambda c: c.type.value)
    assert challenges == [
        aioacme.Challenge(
            type=aioacme.ChallengeType.dns01,
            url=mock.ANY,
            status=aioacme.ChallengeStatus.pending,
            token=mock.ANY,
        ),
        aioacme.Challenge(
            type=aioacme.ChallengeType.dnsaccount01,
            url=mock.ANY,
            status=aioacme.ChallengeStatus.pending,
            token=mock.ANY,
        ),
        aioacme.Challenge(
            type=aioacme.ChallengeType.http01,
            url=mock.ANY,
            status=aioacme.ChallengeStatus.pending,
            token=mock.ANY,
        ),
        aioacme.Challenge(
            type=aioacme.ChallengeType.tlsalpn01,
            url=mock.ANY,
            status=aioacme.ChallengeStatus.pending,
            token=mock.ANY,
        ),
    ]
    assert all(c.url.startswith(pebble_url) for c in challenges)


async def test_finalize__pending_order__error(client, domain, csr):
    # arrange
    created_order = await client.new_order([aioacme.Identifier(domain)])

    # act
    with pytest.raises(aioacme.AcmeError) as exc_info:
        await client.finalize_order(created_order.finalize, csr)

    # assert
    assert exc_info.value.error == aioacme.Error(
        type='urn:ietf:params:acme:error:orderNotReady', detail='Order\'s status ("pending") was not ready'
    )


async def test_answer_challenge__invalid_record_value__challenge_error(client, domain, add_txt):
    order = await client.new_order([aioacme.Identifier(domain)])

    authorization = await client.get_authorization(order.authorizations[0])

    challenge = next(c for c in authorization.challenges if c.type == aioacme.ChallengeType.dns01)

    validation_domain = client.get_dns_challenge_domain(authorization.identifier.value)
    await add_txt(validation_domain, 'foo')

    challenge = await client.answer_challenge(challenge.url)
    assert challenge.status is aioacme.ChallengeStatus.processing

    await anyio.sleep(0.5)

    authorization = await client.get_authorization(authorization.uri)
    assert authorization.status is aioacme.AuthorizationStatus.invalid

    challenge = next(c for c in authorization.challenges if c.type == aioacme.ChallengeType.dns01)
    assert challenge.status is aioacme.ChallengeStatus.invalid
    assert challenge.error == aioacme.Error(
        type='urn:ietf:params:acme:error:unauthorized', detail='Correct value not found for DNS challenge'
    )


async def test_deactivate_authorization(client, domain, add_txt):
    order = await client.new_order([aioacme.Identifier(domain)])

    authorization = await client.get_authorization(order.authorizations[0])

    challenge = next(c for c in authorization.challenges if c.type == aioacme.ChallengeType.dns01)

    validation_domain = client.get_dns_challenge_domain(authorization.identifier.value)
    validation = client.get_dns_challenge_validation(challenge.token)
    await add_txt(validation_domain, validation)

    challenge = await client.answer_challenge(challenge.url)
    assert challenge.status is aioacme.ChallengeStatus.processing

    await anyio.sleep(0.5)

    authorization = await client.get_authorization(authorization.uri)
    assert authorization.status is aioacme.AuthorizationStatus.valid

    authorization = await client.deactivate_authorization(authorization.uri)
    assert authorization.status is aioacme.AuthorizationStatus.deactivated


async def test_integrational_ok(client, domain, csr, add_txt, private_key):
    order = await client.new_order([aioacme.Identifier(domain)])

    authorization = await client.get_authorization(order.authorizations[0])

    challenge = next(c for c in authorization.challenges if c.type == aioacme.ChallengeType.dns01)

    validation_domain = client.get_dns_challenge_domain(authorization.identifier.value)
    validation = client.get_dns_challenge_validation(challenge.token)
    await add_txt(validation_domain, validation)

    challenge = await client.answer_challenge(challenge.url)
    assert challenge.status is aioacme.ChallengeStatus.processing

    await anyio.sleep(0.5)

    authorization = await client.get_authorization(authorization.uri)
    assert authorization.status is aioacme.AuthorizationStatus.valid
    assert authorization.challenges == [
        aioacme.Challenge(
            type=aioacme.ChallengeType.dns01,
            url=challenge.url,
            status=aioacme.ChallengeStatus.valid,
            validated=mock.ANY,
            token=challenge.token,
        )
    ]
    assert isinstance(authorization.challenges[0].validated, datetime)

    order = await client.get_order(order.uri)
    assert order.status is aioacme.OrderStatus.ready

    order = await client.finalize_order(order.finalize, csr)
    assert order.status is aioacme.OrderStatus.processing

    await anyio.sleep(0.5)
    order = await client.get_order(order.uri)
    assert order.status is aioacme.OrderStatus.valid

    certificate = await client.get_certificate(order.certificate)

    assert certificate.startswith(b'---')

    await client.revoke_certificate(x509.load_pem_x509_certificate(certificate), private_key)


async def test_get_account__with_eab__ok(pebble_eab_url):
    account_key = ec.generate_private_key(ec.SECP256R1())
    async with aioacme.Client(
        directory_url=f'{pebble_eab_url}/dir',
        ssl=False,
        account_key=account_key,
        # https://github.com/letsencrypt/pebble/blob/v2.6.0/test/config/pebble-config-external-account-bindings.json
        external_account_binding=aioacme.ExternalAccountBinding(
            kid='kid-1',
            mac_key='zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W',
        ),
    ) as client:
        account = await client.get_account()

    assert account == aioacme.Account(uri=mock.ANY, status=aioacme.AccountStatus.valid, orders=mock.ANY)


@pytest.mark.parametrize(
    'get_new_key',
    [
        pytest.param(lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048), id='RSA_2048'),
        pytest.param(lambda: rsa.generate_private_key(public_exponent=65537, key_size=4096), id='RSA_4096'),
        pytest.param(lambda: ec.generate_private_key(ec.SECP256R1()), id='SECP256R1'),
        pytest.param(lambda: ec.generate_private_key(ec.SECP384R1()), id='SECP384R1'),
        pytest.param(lambda: ec.generate_private_key(ec.SECP521R1()), id='SECP521R1'),
        pytest.param(
            ed25519.Ed25519PrivateKey.generate,
            marks=[pytest.mark.xfail(reason='Ed25519 is not supported')],
            id='Ed25519',
        ),
    ],
)
async def test_change_key(client, domain, get_new_key):
    # arrange
    new_key = get_new_key()

    # act
    await client.change_key(new_key)

    # assert
    await client.new_order([aioacme.Identifier(domain)])
