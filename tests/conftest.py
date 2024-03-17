import asyncio
import uuid

import aiohttp
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import aioacme


@pytest.fixture(scope='session')
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope='session')
async def pebble_url(docker_services, docker_ip) -> str:
    docker_services.start('pebble')
    port = docker_services.port_for('pebble', 14000)
    url = f'https://{docker_ip}:{port}'

    # wait for pebble to be ready
    async with aiohttp.ClientSession() as session:
        for _ in range(100):
            try:
                async with session.get(url, ssl=False):
                    break
            except aiohttp.ClientError as exc:
                last_exc = exc
                await asyncio.sleep(0.1)
        else:
            raise TimeoutError from last_exc

    yield url


@pytest.fixture()
def account_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture()
async def client(pebble_url, account_key) -> aioacme.Client:
    async with aioacme.Client(directory_url=f'{pebble_url}/dir', ssl=False, account_key=account_key) as client:
        yield client


@pytest.fixture()
def domain():
    return f'{uuid.uuid1()}.example.com'


@pytest.fixture(scope='session')
def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture()
def csr(domain, private_key):
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, domain)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(private_key, hashes.SHA256())
    )


@pytest.fixture(name='add_txt')
def add_txt_fixture(docker_services, docker_ip):
    docker_services.start('challtestsrv')
    port = docker_services.wait_for_service('challtestsrv', 8055)

    async def add_txt(domain: str, value: str) -> None:
        async with aiohttp.request(
            'POST', f'http://{docker_ip}:{port}/set-txt', json={'host': domain + '.', 'value': value}
        ) as response:
            response.raise_for_status()

    return add_txt
