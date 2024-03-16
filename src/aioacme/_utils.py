import base64


def int_to_base64url(number: int) -> str:
    return b64_encode(number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')).decode('ascii')


def b64_encode(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b'=')
