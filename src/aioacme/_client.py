import asyncio
import hashlib
import sys
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from ssl import SSLContext
from types import TracebackType
from typing import Any

import aiohttp
import orjson
import serpyco_rs
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from aioacme._directories import LETS_ENCRYPT_STAGING_DIRECTORY
from aioacme._exceptions import AcmeError
from aioacme._jwk import JWK, jwk_thumbprint, make_jwk
from aioacme._jws import jws_encode
from aioacme._models import Authorization, Challenge, Error, Identifier, Order, RevocationReason
from aioacme._types import PrivateKeyTypes
from aioacme._utils import b64_encode

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

_identifier_serializer = serpyco_rs.Serializer(Identifier)
_error_serializer = serpyco_rs.Serializer(Error)
_authorization_serializer = serpyco_rs.Serializer(Authorization)
_order_serializer = serpyco_rs.Serializer(Order)
_challenge_serializer = serpyco_rs.Serializer(Challenge)


class Client:
    _DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'

    def __init__(
        self,
        *,
        account_key: PrivateKeyTypes,
        directory_url: str = LETS_ENCRYPT_STAGING_DIRECTORY,
        account_uri: str | None = None,
        ssl: SSLContext | bool = True,
    ) -> None:
        """
        Create new ACME client.

        :param account_key: private key for account.
        :param directory_url: URL to get directory.
        :param account_uri: Optional account uri, if not provided, it would be fetched on first request.
        :param ssl: SSL context.
        """
        self._account_key = account_key
        self._directory_url = directory_url
        self._account_uri = account_uri

        self._account_key_jwk = make_jwk(self._account_key)
        self._account_key_jwk_thumbprint = jwk_thumbprint(self._account_key_jwk)

        self._directory: _Directory | None = None
        self._session: aiohttp.ClientSession = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ssl), cookie_jar=aiohttp.DummyCookieJar()
        )

        self._nonces: list[str] = []
        self._get_nonce_lock = asyncio.Lock()

    async def new_order(self, identifiers: Sequence[Identifier]) -> Order:
        """
        Create new certificate order.

        :param identifiers: list of identifiers (domains or ips).
        :return: created order.
        """
        url = (await self._get_directory()).new_order
        async with self._request(
            url,
            data={'identifiers': [_identifier_serializer.dump(i) for i in identifiers]},
        ) as response:
            response_data = await response.json(loads=orjson.loads)
        return _order_serializer.load({**response_data, 'uri': response.headers['Location']})

    async def get_order(self, order_uri: str) -> Order:
        """
        Get existing order.

        :param order_uri: order URI.
        :return: order.
        """
        async with self._request(order_uri) as response:
            response_data = await response.json(loads=orjson.loads)
        return _order_serializer.load({**response_data, 'uri': order_uri})

    async def get_authorization(self, authorization_uri: str) -> Authorization:
        """
        Get existing authorization.

        :param authorization_uri: authorization URI.
        :return: authorization.
        """
        async with self._request(authorization_uri) as response:
            response_data = await response.json(loads=orjson.loads)
        return _authorization_serializer.load({**response_data, 'uri': authorization_uri})

    def get_dns_challenge_domain(self, domain: str) -> str:
        """
        Generate domain for DNS challenge.

        :param domain: domain.
        :return: ACME challenge domain.
        """
        return f'_acme-challenge.{domain}'

    def get_dns_challenge_validation(self, token: str) -> str:
        """
        Generate TXT record for DNS challenge.

        :param token: challenge token.
        :return: value for TXT record.
        """
        return b64_encode(
            hashlib.sha256(f'{token}.{self._account_key_jwk_thumbprint}'.encode('ascii')).digest()
        ).decode('ascii')

    async def answer_challenge(self, url: str) -> Challenge:
        """
        Respond to the challenge.

        https://datatracker.ietf.org/doc/html/rfc8555#section-7.5.1

        :param url: challenge url.
        """
        async with self._request(url, data={}) as response:
            response_data = await response.json(loads=orjson.loads)
        return _challenge_serializer.load(response_data)

    async def deactivate_authorization(self, uri: str) -> Authorization:
        """
        Deactivate authorization.

        https://datatracker.ietf.org/doc/html/rfc8555#section-7.5.2

        :param uri: authorization URI.
        :return: authorization with updated fields.
        """
        async with self._request(uri, data={'status': 'deactivated'}) as response:
            response_data = await response.json(loads=orjson.loads)
        return _authorization_serializer.load({**response_data, 'uri': uri})

    async def finalize_order(self, finalize: str, csr: x509.CertificateSigningRequest) -> Order:
        """
        Finalize the order by submitting the CSR to issue certificate.

        :param finalize: finalize uri.
        :param csr: CSR.
        :return: order with updated fields.
        """
        async with self._request(
            finalize,
            data={'csr': b64_encode(csr.public_bytes(serialization.Encoding.DER)).decode('ascii')},
        ) as response:
            response_data = await response.json(loads=orjson.loads)
        return _order_serializer.load({**response_data, 'uri': response.headers['Location']})

    async def get_certificate(self, certificate: str) -> bytes:
        """
        Download ready certificate

        :param certificate: certificate URL.
        :return: certificate in PEM format.
        """
        async with self._request(certificate) as response:
            return await response.read()

    async def revoke_certificate(
        self,
        certificate: x509.Certificate,
        key: PrivateKeyTypes | None = None,
        reason: RevocationReason = RevocationReason.unspecified,
    ) -> None:
        """
        Revoke certificate.

        https://datatracker.ietf.org/doc/html/rfc8555#section-7.6

        :param certificate: certificate.
        :param key: private key, if you want to revoke certificate without account key.
        :param reason: reason.
        """
        async with self._request(
            (await self._get_directory()).revoke_cert,
            data={
                'certificate': b64_encode(certificate.public_bytes(serialization.Encoding.DER)).decode('ascii'),
                'reason': reason.value,
            },
            jwk=make_jwk(key) if key else None,
            key=key,
        ):
            pass

    async def deactivate_account(self) -> None:
        """
        Deactivate account.

        https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.6
        """
        async with self._request((await self.get_account_uri()), data={'status': 'deactivated'}):
            pass

    async def change_key(self, new_account_key: PrivateKeyTypes) -> None:
        """
        Change private key for current account.
        Further requests will be signed with this new key.

        https://datatracker.ietf.org/doc/html/rfc8555#section-7.6

        :param new_account_key: new private key.
        """
        new_account_key_jwk = make_jwk(new_account_key)

        url = (await self._get_directory()).key_change
        payload = await self._wrap_in_jws(
            url=url,
            data={
                'account': await self.get_account_uri(),
                'oldKey': self._account_key_jwk,
            },
            key=new_account_key,
            jwk=new_account_key_jwk,
            add_nonce=False,
        )
        async with self._request(url, data=payload):
            pass
        self._account_key = new_account_key
        self._account_key_jwk = new_account_key_jwk
        self._account_key_jwk_thumbprint = jwk_thumbprint(new_account_key_jwk)

    async def get_account_uri(self) -> str:
        """
        Get current account URI.
        :return: URI.
        """
        if self._account_uri is None:
            async with self._request(
                url=(await self._get_directory()).new_account,
                data={'termsOfServiceAgreed': True},
                jwk=self._account_key_jwk,
            ) as response:
                self._account_uri = response.headers['Location']

        return self._account_uri

    @asynccontextmanager
    async def _request(
        self,
        url: str,
        *,
        data: Mapping[str, Any] | bytes = b'',
        jwk: JWK | None = None,
        key: PrivateKeyTypes | None = None,
    ) -> AsyncIterator[aiohttp.ClientResponse]:
        async with self._session.post(
            url,
            data=await self._wrap_in_jws(url=url, data=data, jwk=jwk, key=key),
            headers={'Content-Type': 'application/jose+json'},
        ) as response:
            self._add_nounce(response)

            if response.status < 300:
                yield response
                return

            try:
                error = _error_serializer.load(await response.json(loads=orjson.loads))
            except aiohttp.ContentTypeError:
                error = Error(type='unknown', detail='')

            if error.type != 'urn:ietf:params:acme:error:badNonce':
                raise AcmeError(error)

            # retry bad nonce
            async with self._request(url, data=data, jwk=jwk, key=key) as retried_response:
                yield retried_response

    async def _wrap_in_jws(  # noqa: PLR0913
        self,
        *,
        url: str,
        data: Mapping[str, Any] | bytes,
        jwk: JWK | None = None,
        key: PrivateKeyTypes | None = None,
        add_nonce: bool = True,
    ) -> bytes:
        headers: dict[str, Any] = {'url': url}
        if jwk:
            headers['jwk'] = jwk
        else:
            headers['kid'] = await self.get_account_uri()

        if add_nonce:
            headers['nonce'] = await self._get_nonce()

        payload = orjson.dumps(data) if not isinstance(data, bytes) else data
        return jws_encode(payload=payload, key=key or self._account_key, headers=headers)

    async def _get_nonce(self) -> str:
        async with self._get_nonce_lock:
            if not self._nonces:
                async with self._session.head((await self._get_directory()).new_nonce) as response:
                    self._nonces.append(response.headers['Replay-Nonce'])
            return self._nonces.pop()

    def _add_nounce(self, response: aiohttp.ClientResponse) -> None:
        self._nonces.append(response.headers['Replay-Nonce'])

    async def _get_directory(self) -> '_Directory':
        if self._directory is None:
            async with self._session.get(self._directory_url) as response:
                response_data = await response.json(loads=orjson.loads)

            self._directory = _Directory(
                new_account=response_data['newAccount'],
                new_nonce=response_data['newNonce'],
                new_order=response_data['newOrder'],
                revoke_cert=response_data['revokeCert'],
                key_change=response_data['keyChange'],
            )

        return self._directory

    async def close(self) -> None:
        await self._session.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        await asyncio.shield(self.close())


@dataclass(frozen=True, slots=True)
class _Directory:
    new_account: str
    new_nonce: str
    new_order: str
    revoke_cert: str
    key_change: str
