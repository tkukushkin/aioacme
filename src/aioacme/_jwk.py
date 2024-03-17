import hashlib
import sys
from collections.abc import Mapping
from typing import Any, NewType

import orjson
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from aioacme._types import PrivateKeyTypes
from aioacme._utils import b64_encode, int_to_base64url

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

        return JWK(
            {
                'kty': 'EC',
                'crv': crv,
                'x': int_to_base64url(ec_public_numbers.x),
                'y': int_to_base64url(ec_public_numbers.y),
            }
        )

    if isinstance(key, rsa.RSAPrivateKey):  # pragma: no branch
        rsa_public_numbers = key.public_key().public_numbers()
        return JWK(
            {
                'kty': 'RSA',
                'e': int_to_base64url(rsa_public_numbers.e),
                'n': int_to_base64url(rsa_public_numbers.n),
            }
        )

    assert_never(key)


def jwk_thumbprint(jwk: JWK) -> str:
    jwk_str = orjson.dumps(jwk, option=orjson.OPT_SORT_KEYS)
    jwk_hash = hashlib.sha256(jwk_str).digest()
    return b64_encode(jwk_hash).decode('ascii')
