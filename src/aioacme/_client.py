import asyncio
import hashlib
import sys
from base64 import b64decode
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from ssl import SSLContext
from types import TracebackType
from typing import Any, Final, Literal

import aiohttp
import orjson
import serpyco_rs
from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac, serialization

from aioacme._directories import LETS_ENCRYPT_STAGING_DIRECTORY
from aioacme._exceptions import AcmeError
from aioacme._jwk import JWK, jwk_thumbprint, make_jwk
from aioacme._jws import jws_encode
from aioacme._models import (
    Account,
    AccountStatus,
    Authorization,
    Challenge,
    Error,
    ExternalAccountBinding,
    Identifier,
    Order,
    RevocationReason,
)
from aioacme._types import PrivateKeyTypes
from aioacme._utils import b64_encode

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

_account_serializer = serpyco_rs.Serializer(Account, camelcase_fields=True)
_identifier_serializer = serpyco_rs.Serializer(Identifier, camelcase_fields=True)
_error_serializer = serpyco_rs.Serializer(Error, camelcase_fields=True)
_authorization_serializer = serpyco_rs.Serializer(Authorization, camelcase_fields=True)
_order_serializer = serpyco_rs.Serializer(Order, camelcase_fields=True)
_challenge_serializer = serpyco_rs.Serializer(Challenge, camelcase_fields=True)


class Client:
    account_key: PrivateKeyTypes
    directory_url: Final[str]
    account_uri: str | None
    external_account_binding: ExternalAccountBinding | None

    def __init__(
        self,
        *,
        account_key: PrivateKeyTypes,
        directory_url: str = LETS_ENCRYPT_STAGING_DIRECTORY,
        account_uri: str | None = None,
        external_account_binding: ExternalAccountBinding | None = None,
        ssl: SSLContext | bool = True,
    ) -> None:
        """
        Create new ACME client.

        By using this library you agree to the terms of service of the ACME server you are using.

        :param account_key: private key for account.
        :param directory_url: URL to get directory.
        :param account_uri: optional account URI, if not provided, it would be fetched on first request.
        :param ssl: SSL context.
        """
        self.account_key = account_key
        self.directory_url = directory_url
        self.account_uri = account_uri
        self.external_account_binding = external_account_binding

        self._account_key_jwk = make_jwk(self.account_key)
        self._account_key_jwk_thumbprint = jwk_thumbprint(self._account_key_jwk)

        self._directory: _Directory | None = None
        self._session: aiohttp.ClientSession = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ssl), cookie_jar=aiohttp.DummyCookieJar()
        )

        self._nonces: list[str] = []
        self._get_nonce_lock = asyncio.Lock()

    async def get_terms_of_service(self) -> str | None:
        return (await self._get_directory()).terms_of_service

    async def get_account(self) -> Account:
        """
        Get account info.

        Registers new account if it doesn't exist.
        """
        data: Any
        if self.account_uri is None:
            url = (await self._get_directory()).new_account
            data = {'termsOfServiceAgreed': True}
            jwk = self._account_key_jwk
            if self.external_account_binding:
                mac_key = self.external_account_binding.mac_key
                mac_key = b64decode(mac_key) if isinstance(mac_key, str) else mac_key
                data['externalAccountBinding'] = orjson.loads(
                    jws_encode(
                        key=hmac.HMAC(mac_key, hashes.SHA256()),
                        headers={'kid': self.external_account_binding.kid, 'url': url},
                        payload=orjson.dumps(jwk),
                    )
                )
        else:
            url = self.account_uri
            data = b''
            jwk = None

        async with self._request(url=url, data=data, jwk=jwk) as response:
            response_data = await response.json(loads=orjson.loads)

        account = _account_serializer.load({**response_data, 'uri': self.account_uri or response.headers['Location']})
        self.account_uri = account.uri
        return account

    async def update_account(
        self, *, contact: Sequence[str] | None = None, status: Literal[AccountStatus.deactivated] | None = None
    ) -> Account:
        """
        Update account info.

        :param contact: list of contacts.
        :param status: new account status, accepts only :attr:`.AccountStatus.deactivated`.
        """
        uri = await self._get_account_uri()
        data: dict[str, Any] = {}
        if contact is not None:
            data['contact'] = contact
        if status is not None:
            data['status'] = status.value
        async with self._request(url=uri, data=data) as response:
            response_data = await response.json(loads=orjson.loads)

        return _account_serializer.load({**response_data, 'uri': uri})

    async def new_order(
        self,
        identifiers: Sequence[Identifier],
        *,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
    ) -> Order:
        """
        Create new certificate order.

        :param identifiers: list of identifiers (domains or ips).
        :param not_before: the requested value of the notBefore field in the certificate.
        :param not_after: the requested value of the notAfter field in the certificate.
        """
        url = (await self._get_directory()).new_order

        data: dict[str, Any] = {'identifiers': [_identifier_serializer.dump(i) for i in identifiers]}
        if not_before is not None:
            data['notBefore'] = not_before.isoformat()
        if not_after is not None:
            data['notAfter'] = not_after.isoformat()

        async with self._request(url, data=data) as response:
            response_data = await response.json(loads=orjson.loads)

        return _order_serializer.load({**response_data, 'uri': response.headers['Location']})

    async def get_order(self, order_uri: str) -> Order:
        """
        Get existing order.

        :param order_uri: order URI.
        """
        async with self._request(order_uri) as response:
            response_data = await response.json(loads=orjson.loads)
        return _order_serializer.load({**response_data, 'uri': order_uri})

    async def get_authorization(self, authorization_uri: str) -> Authorization:
        """
        Get existing authorization.

        :param authorization_uri: authorization URI.
        """
        async with self._request(authorization_uri) as response:
            response_data = await response.json(loads=orjson.loads)
        return _authorization_serializer.load({**response_data, 'uri': authorization_uri})

    def get_dns_challenge_domain(self, domain: str) -> str:
        """
        Generate domain for DNS challenge.

        :param domain: domain.
        """
        return f'_acme-challenge.{domain}'

    def get_dns_challenge_validation(self, token: str) -> str:
        """
        Generate TXT record value for DNS challenge.

        :param token: challenge token.
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
        """
        async with self._request(uri, data={'status': 'deactivated'}) as response:
            response_data = await response.json(loads=orjson.loads)
        return _authorization_serializer.load({**response_data, 'uri': uri})

    async def finalize_order(self, finalize: str, csr: x509.CertificateSigningRequest) -> Order:
        """
        Finalize the order by submitting the CSR to issue certificate.

        :param finalize: finalize uri.
        :param csr: CSR.
        """
        async with self._request(
            finalize,
            data={'csr': b64_encode(csr.public_bytes(serialization.Encoding.DER)).decode('ascii')},
        ) as response:
            response_data = await response.json(loads=orjson.loads)
        return _order_serializer.load({**response_data, 'uri': response.headers['Location']})

    async def get_certificate(self, certificate: str) -> bytes:
        """
        Download ready certificate in PEM format.

        :param certificate: certificate URL.
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
                'account': await self._get_account_uri(),
                'oldKey': self._account_key_jwk,
            },
            key=new_account_key,
            jwk=new_account_key_jwk,
            add_nonce=False,
        )
        async with self._request(url, data=payload):
            pass
        self.account_key = new_account_key
        self._account_key_jwk = new_account_key_jwk
        self._account_key_jwk_thumbprint = jwk_thumbprint(new_account_key_jwk)

    async def _get_account_uri(self) -> str:
        return self.account_uri or (await self.get_account()).uri

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

    async def _wrap_in_jws(
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
            headers['kid'] = await self._get_account_uri()

        if add_nonce:
            headers['nonce'] = await self._get_nonce()

        payload = orjson.dumps(data) if not isinstance(data, bytes) else data
        return jws_encode(payload=payload, key=key or self.account_key, headers=headers)

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
            async with self._session.get(self.directory_url) as response:
                response_data = await response.json(loads=orjson.loads)

            self._directory = _Directory(
                new_account=response_data['newAccount'],
                new_nonce=response_data['newNonce'],
                new_order=response_data['newOrder'],
                revoke_cert=response_data['revokeCert'],
                key_change=response_data['keyChange'],
                terms_of_service=response_data.get('meta', {}).get('termsOfService'),
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
    terms_of_service: str | None = None
