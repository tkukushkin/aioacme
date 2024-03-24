import base64


def b64_encode(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b'=')
