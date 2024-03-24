import binascii
import sys
from collections.abc import Mapping
from typing import Any

import orjson
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from aioacme._types import PrivateKeyTypes
from aioacme._utils import b64_encode

if sys.version_info >= (3, 11):
    from typing import assert_never
else:
    from typing_extensions import assert_never


def jws_encode(
    payload: bytes,
    key: PrivateKeyTypes,
    headers: Mapping[str, Any],
) -> bytes:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        alg = {ec.SECP256R1.name: 'ES256', ec.SECP384R1.name: 'ES384', ec.SECP521R1.name: 'ES512'}[key.curve.name]
    elif isinstance(key, rsa.RSAPrivateKey):
        alg = 'RS256'
    elif isinstance(key, ed25519.Ed25519PrivateKey):
        alg = 'EdDSA'
    else:
        assert_never(key)

    headers = {**headers, 'alg': alg}

    headers_b64 = b64_encode(orjson.dumps(headers))
    payload_b64 = b64_encode(payload)
    signing_input = headers_b64 + b'.' + payload_b64

    if isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(signing_input, PKCS1v15(), hashes.SHA256())
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        hash_alg = {
            ec.SECP256R1.name: hashes.SHA256(),
            ec.SECP384R1.name: hashes.SHA384(),
            ec.SECP521R1.name: hashes.SHA512(),
        }[key.curve.name]
        signature = key.sign(signing_input, ec.ECDSA(hash_alg))
        signature = _der_to_raw_signature(signature, key.curve)
    elif isinstance(key, ed25519.Ed25519PrivateKey):
        signature = key.sign(signing_input)
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
