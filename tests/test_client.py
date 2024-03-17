import asyncio
from datetime import datetime
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

import aioacme


async def test_get_account_uri(client, pebble_url):
    # act
    account_uri = await client.get_account_uri()

    # assert
    assert account_uri.startswith(f'{pebble_url}/my-account')


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
        not_before=None,
        not_after=None,
        error=None,
        certificate=None,
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

    await asyncio.sleep(0.5)

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

    await asyncio.sleep(0.5)

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

    await asyncio.sleep(0.5)

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

    await asyncio.sleep(0.5)
    order = await client.get_order(order.uri)
    assert order.status is aioacme.OrderStatus.valid

    certificate = await client.get_certificate(order.certificate)

    assert certificate.startswith(b'---')

    await client.revoke_certificate(x509.load_pem_x509_certificate(certificate), private_key)


async def test_deactivate_account(client, domain):
    # act
    await client.deactivate_account()

    # assert
    with pytest.raises(aioacme.AcmeError) as exc_info:
        await client.new_order([aioacme.Identifier(domain)])

    assert exc_info.value.error == aioacme.Error(
        type='urn:ietf:params:acme:error:unauthorized', detail='Account has been deactivated'
    )


async def test_change_key(client, domain):
    # arrange
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # act
    await client.change_key(new_key)

    # assert
    await client.new_order([aioacme.Identifier(domain)])
