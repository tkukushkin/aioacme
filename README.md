# aioacme

[![PyPI - Status](https://img.shields.io/pypi/status/aioacme)](https://pypi.org/project/aioacme)
[![PyPI](https://img.shields.io/pypi/v/aioacme)](https://pypi.org/project/aioacme)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/aioacme)](https://pypi.org/project/aioacme)
[![PyPI - License](https://img.shields.io/pypi/l/aioacme)](https://pypi.org/project/aioacme)
[![CI Status](https://github.com/tkukushkin/aioacme/actions/workflows/check.yml/badge.svg)](https://github.com/tkukushkin/aioacme/actions/workflows/check.yml)
[![codecov](https://codecov.io/gh/tkukushkin/aioacme/graph/badge.svg?token=376OQ1J9YH)](https://codecov.io/gh/tkukushkin/aioacme)

Simple async client for ACME protocol.

## Installation

```bash
pip install aioacme
```

## Usage

Issue certificate with DNS-01 challenge:

```python
import asyncio

import aioacme
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

async def main():
    account_key = serialization.load_pem_private_key(...)
    
    async with aioacme.Client(
        account_key=account_key, 
        directory_url=aioacme.LETS_ENCRYPT_STAGING_DIRECTORY
    ) as client:
        order = await client.new_order([aioacme.Identifier("example.com")])
        
        for authorization_uri in order.authorizations:
            authorization = await client.get_authorization(authorization_uri)
            
            if authorization.status is aioacme.AuthorizationStatus.valid:
                # authorization reused
                continue
            
            challenge = next(
                c for c in authorization.challenges if c.type is aioacme.ChallengeType.dns01
            )
            
            domain = client.get_dns_challenge_domain(authorization.identifier.value)
            validation = client.get_dns_challenge_validation(challenge.token)
            
            print(f"Please add TXT record {domain} with the following content: {validation}")
            input("Press Enter when TXT record is created")
            
            await client.answer_challenge(challenge.url)
            
            while authorization.status not in (
                aioacme.AuthorizationStatus.valid,
                aioacme.AuthorizationStatus.invalid
            ):
                await asyncio.sleep(1)
                authorization = await client.get_authorization(authorization_uri)
            
            if authorization.status is aioacme.AuthorizationStatus.invalid:
                raise Exception(f"Authorization status is invalid: {authorization}")
            
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(x509.NameOID.COMMON_NAME, "example.com")
            ]))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("example.com")
            ]), critical=False)
            .sign(key, hashes.SHA256())
        )
        order = await client.finalize_order(order.finalize, csr)
        
        while order.status not in {aioacme.OrderStatus.valid, aioacme.OrderStatus.invalid}:
            await asyncio.sleep(1)
            order = await client.get_order(order.uri)
            
        if order.status is aioacme.OrderStatus.invalid:
            raise Exception(f"Order status is invalid: {order}")
        
        cert = await client.get_certificate(order.certificate)
        print(cert.decode("ascii"))
        
        
asyncio.run(main())
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
