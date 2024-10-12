import ssl
import uuid

import anyio
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from lovely.pytest.docker.compose import Services

import aioacme


@pytest.fixture(autouse=True, scope='session', params=['asyncio', 'trio'])
def anyio_backend(request) -> str:
    return request.param


@pytest.fixture(scope='session')
async def pebble_url(docker_services: Services, docker_ip: str) -> str:
    return await _get_pebble_url(docker_services, docker_ip, 'pebble')


@pytest.fixture(scope='session')
async def pebble_eab_url(docker_services: Services, docker_ip: str) -> str:
    return await _get_pebble_url(docker_services, docker_ip, 'pebble-eab')


async def _get_pebble_url(docker_services: Services, docker_ip: str, name: str) -> str:
    docker_services.start(name)
    port = docker_services.port_for(name, 14000)
    url = f'https://{docker_ip}:{port}'

    # wait for pebble to be ready
    last_exc = None
    async with httpx.AsyncClient(verify=False) as client:
        for _ in range(100):
            try:
                await client.get(url)
            except (httpx.HTTPError, ssl.SSLZeroReturnError) as exc:
                last_exc = exc
                await anyio.sleep(0.1)
            else:
                break
        else:
            raise TimeoutError from last_exc
    return url


@pytest.fixture()
async def client(pebble_url):
    account_key = ec.generate_private_key(ec.SECP256R1())
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
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f'http://{docker_ip}:{port}/set-txt', json={'host': domain + '.', 'value': value}
            )
            response.raise_for_status()

    return add_txt
