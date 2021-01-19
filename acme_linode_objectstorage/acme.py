"""
ACME client for Let's Encrypt.

See RFC-8555.
"""

import base64
import hashlib
import math
import json
import time
from typing import Optional, List, Set

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding


class AcmeClient:
    DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory'

    def __init__(self, account_key: rsa.RSAPrivateKeyWithSerialization):
        self.http = requests.Session()
        self.account_key = account_key

        self._directory = None
        self._nonce = None
        self._key_id = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.http.close()

    def new_account(self, terms_of_service_agreed: Optional[bool] = None, only_existing: Optional[bool] = None) -> 'Account':
        payload = {}

        if terms_of_service_agreed is not None:
            payload['termsOfServiceAgreed'] = terms_of_service_agreed

        if only_existing is not None:
            payload['onlyReturnExisting'] = only_existing

        public_jwk = rsa_jwk_public(self.account_key)
        r = self._signed_request(self.url_for('newAccount'), payload, {'alg': 'RS256', 'jwk': public_jwk})
        self._key_id = r.headers['Location']

        return Account(self, r.headers['Location'], r.json())

    def new_order(self, domains: List[str]) -> 'Order':
        payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}

        r = self.signed_request(self.url_for('newOrder'), payload)

        return Order(self, r.headers['Location'], r.json())

    def url_for(self, resource: str) -> str:
        if not self._directory:
            r = self.http.get(self.DIRECTORY_URL)
            r.raise_for_status()

            self._directory = r.json()

        return self._directory[resource]

    def signed_request(self, url: str, payload: Optional[dict] = None) -> requests.Response:
        if not self._key_id:
            self.new_account(only_existing=True)

        return self._signed_request(url, payload, {'alg': 'RS256', 'kid': self._key_id})

    def _signed_request(self, url: str, payload: Optional[dict], key: dict) -> requests.Response:
        if not self._nonce:
            self._new_nonce()

        protected = b64url(json_encode(dict({'url': url, 'nonce': self._nonce}, **key)))
        payload = b64url(json_encode(payload)) if payload is not None else ""
        signature = b64url(self.account_key.sign(f'{protected}.{payload}'.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256()))

        headers = {'Content-Type': 'application/jose+json'}
        data = {'protected': protected, 'payload': payload, 'signature': signature}
        r = self.http.post(url, headers=headers, json=data)
        self._nonce = r.headers.get('Replay-Nonce')
        r.raise_for_status()

        return r

    def _new_nonce(self):
        r = self.http.head(self.url_for('newNonce'))
        r.raise_for_status()

        self._nonce = r.headers['Replay-Nonce']


class Resource:
    POLL_INTERVAL = 1

    def __init__(self, client: AcmeClient, url: str, data: Optional[dict] = None):
        self.client = client
        self.url = url
        self._data = data
        self._retry_after = time.monotonic()

    @property
    def status(self) -> dict:
        return self['status']

    def update(self):
        r = self.client.signed_request(self.url)

        self._retry_after = time.monotonic() + int(r.headers.get('Retry-After', self.POLL_INTERVAL))
        self._data = r.json()

    def poll_until_not(self, statuses: Set[str]):
        while self.status in statuses:
            delay = self._retry_after - time.monotonic()
            if delay > 0:
                time.sleep(delay)

            self.update()

    def __getitem__(self, item):
        if self._data is None:
            self.update()

        return self._data[item]

    def __repr__(self):
        data = repr(self._data) if self._data is not None else '...'
        return f'<{self.__class__.__name__} {self.url} {data}>'


class Account(Resource):
    @property
    def key(self) -> dict:
        return self['key']

    @property
    def key_thumbprint(self) -> str:
        return json_thumbprint(self.key)


class Order(Resource):
    @property
    def authorizations(self) -> List['Authorization']:
        return [Authorization(self.client, url) for url in self['authorizations']]

    def finalize(self, csr: x509.CertificateSigningRequest):
        if self.status != 'ready':
            raise RuntimeError(f'Invalid state: {self.status}')

        csr = b64url(csr.public_bytes(serialization.Encoding.DER))

        r = self.client.signed_request(self['finalize'], {'csr': csr})
        self._data = r.json()

    def certificate(self) -> str:
        if self.status != 'valid':
            raise RuntimeError(f'Invalid state: {self.status}')

        r = self.client.signed_request(self['certificate'])
        return r.text


class Authorization(Resource):
    @property
    def identifier(self) -> dict:
        return self['identifier']

    @property
    def challenges(self) -> List['Challenge']:
        return [Challenge(self.client, challenge['url'], challenge) for challenge in self['challenges']]


class Challenge(Resource):
    @property
    def type(self) -> str:
        return self['type']

    def respond(self):
        r = self.client.signed_request(self.url, {})
        self._data = r.json()


def rsa_jwk_public(key: rsa.RSAPrivateKeyWithSerialization):
    if not isinstance(key, rsa.RSAPrivateKeyWithSerialization):
        raise TypeError('Not a serializable RSA key')

    private = key.private_numbers()

    return {
        'kty': 'RSA',
        'n': b64url_uint(private.public_numbers.n),
        'e': b64url_uint(private.public_numbers.e),
    }


def b64url_uint(n: int) -> str:
    if n < 0:
        raise TypeError('Must be unsigned integer')

    length = int(math.log2(n) / 8) + 1 if n != 0 else 0
    return b64url(n.to_bytes(length, 'big'))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def json_thumbprint(data: dict) -> str:
    return b64url(hashlib.sha256(json_encode(data)).digest())


def json_encode(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
