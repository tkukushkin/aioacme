# aioacme

[![PyPI - Status](https://img.shields.io/pypi/status/aioacme)](https://pypi.org/project/aioacme)
[![PyPI](https://img.shields.io/pypi/v/aioacme)](https://pypi.org/project/aioacme)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/aioacme)](https://pypi.org/project/aioacme)
[![PyPI - License](https://img.shields.io/pypi/l/aioacme)](https://pypi.org/project/aioacme)

Simple async client for ACME protocol.

## Installation

```bash
pip install aioacme
```

## Usage

```python
import aioacme
from cryptography.hazmat.primitives import serialization

async def main():
    private_key = serialization.load_pem_private_key(...)
    
    async with aioacme.Client(private_key=private_key, directory_url=...) as client:
        order = await client.new_order([aioacme.Identifier("example.com")])
        ...
```


## License

This project is licensed under the MIT License - see the LICENSE file for details.
