import binascii
import sys
from collections.abc import Mapping
from typing import Any

import orjson
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
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
        alg = f'ES{key.curve.key_size}'
        hash_alg = {256: hashes.SHA256, 384: hashes.SHA384}[key.curve.key_size]()
    elif isinstance(key, rsa.RSAPrivateKey):
        alg = 'RS256'
        hash_alg = hashes.SHA256()
    else:
        assert_never(key)

    headers = {**headers, 'alg': alg}

    headers_b64 = b64_encode(orjson.dumps(headers))
    payload_b64 = b64_encode(payload)
    signing_input = headers_b64 + b'.' + payload_b64

    if isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(signing_input, PKCS1v15(), hash_alg)
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        signature = key.sign(signing_input, ec.ECDSA(hash_alg))
        signature = _der_to_raw_signature(signature, key.curve)
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
    num_bits = curve.key_size
    num_bytes = (num_bits + 7) // 8

    r, s = decode_dss_signature(der_sig)

    return _number_to_bytes(r, num_bytes) + _number_to_bytes(s, num_bytes)


def _number_to_bytes(num: int, num_bytes: int) -> bytes:
    padded_hex = '%0*x' % (2 * num_bytes, num)
    return binascii.a2b_hex(padded_hex.encode('ascii'))
