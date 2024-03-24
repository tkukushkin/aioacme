import hashlib
import sys
from collections.abc import Mapping
from typing import Any, NewType

import orjson
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from aioacme._types import PrivateKeyTypes
from aioacme._utils import b64_encode

if sys.version_info >= (3, 11):
    from typing import assert_never
else:
    from typing_extensions import assert_never

JWK = NewType('JWK', Mapping[str, Any])


def make_jwk(key: PrivateKeyTypes) -> JWK:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        ec_public_key = key.public_key()
        ec_public_numbers = ec_public_key.public_numbers()

        crv = {'secp256r1': 'P-256', 'secp384r1': 'P-384', 'secp521r1': 'P-521'}[ec_public_key.curve.name]
        byte_length = (ec_public_key.curve.key_size + 7) // 8

        return JWK(
            {
                'kty': 'EC',
                'crv': crv,
                'x': _int_to_base64url(ec_public_numbers.x, byte_length=byte_length),
                'y': _int_to_base64url(ec_public_numbers.y, byte_length=byte_length),
            }
        )

    if isinstance(key, rsa.RSAPrivateKey):
        rsa_public_numbers = key.public_key().public_numbers()
        return JWK(
            {
                'kty': 'RSA',
                'e': _int_to_base64url(rsa_public_numbers.e),
                'n': _int_to_base64url(rsa_public_numbers.n),
            }
        )

    if isinstance(key, ed25519.Ed25519PrivateKey):
        return JWK(
            {
                'kty': 'OKP',
                'crv': 'Ed25519',
                'x': b64_encode(
                    key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                ).decode('ascii'),
            }
        )

    assert_never(key)


def jwk_thumbprint(jwk: JWK) -> str:
    jwk_str = orjson.dumps(jwk, option=orjson.OPT_SORT_KEYS)
    jwk_hash = hashlib.sha256(jwk_str).digest()
    return b64_encode(jwk_hash).decode('ascii')


def _int_to_base64url(number: int, *, byte_length: int | None = None) -> str:
    byte_length = byte_length or (number.bit_length() + 7) // 8
    return b64_encode(number.to_bytes(byte_length, byteorder='big')).decode('ascii')
