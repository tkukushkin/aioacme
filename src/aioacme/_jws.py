import binascii
import sys
from collections.abc import Mapping
from typing import Any

import orjson
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from aioacme._types import PrivateKeyTypes
from aioacme._utils import b64_encode

if sys.version_info >= (3, 11):
    from typing import assert_never
else:
    from typing_extensions import assert_never

_EC_ALGS: Mapping[type[ec.EllipticCurve], str] = {ec.SECP256R1: 'ES256', ec.SECP384R1: 'ES384', ec.SECP521R1: 'ES512'}
_EC_HASHES: Mapping[type[ec.EllipticCurve], hashes.HashAlgorithm] = {
    ec.SECP256R1: hashes.SHA256(),
    ec.SECP384R1: hashes.SHA384(),
    ec.SECP521R1: hashes.SHA512(),
}


def jws_encode(
    payload: bytes,
    key: PrivateKeyTypes | hmac.HMAC,
    headers: Mapping[str, Any],
) -> bytes:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        alg = _EC_ALGS[type(key.curve)]
    elif isinstance(key, rsa.RSAPrivateKey):
        alg = 'RS256'
    elif isinstance(key, ed25519.Ed25519PrivateKey):
        alg = 'EdDSA'
    elif isinstance(key, hmac.HMAC):
        alg = f'HS{key.algorithm.digest_size * 8}'
    else:
        assert_never(key)

    headers = {**headers, 'alg': alg}

    headers_b64 = b64_encode(orjson.dumps(headers))
    payload_b64 = b64_encode(payload)
    signing_input = headers_b64 + b'.' + payload_b64

    if isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(signing_input, PKCS1v15(), hashes.SHA256())
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        hash_alg = _EC_HASHES[type(key.curve)]
        signature = key.sign(signing_input, ec.ECDSA(hash_alg))
        signature = _der_to_raw_signature(signature, key.curve)
    elif isinstance(key, ed25519.Ed25519PrivateKey):
        signature = key.sign(signing_input)
    elif isinstance(key, hmac.HMAC):
        key = key.copy()
        key.update(signing_input)
        signature = key.finalize()
    else:
        assert_never(key)

    return orjson.dumps(
        {
            'protected': headers_b64.decode('ascii'),
            'payload': payload_b64.decode('ascii'),
            'signature': b64_encode(signature).decode('ascii'),
        }
    )


def _der_to_raw_signature(der_sig: bytes, curve: ec.EllipticCurve) -> bytes:
    num_bytes = (curve.key_size + 7) // 8

    r, s = decode_dss_signature(der_sig)

    return _number_to_bytes(r, num_bytes) + _number_to_bytes(s, num_bytes)


def _number_to_bytes(num: int, num_bytes: int) -> bytes:
    padded_hex = '%0*x' % (2 * num_bytes, num)
    return binascii.a2b_hex(padded_hex.encode('ascii'))
