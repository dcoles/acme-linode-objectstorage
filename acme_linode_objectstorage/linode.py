"""
Linode API client.

See https://www.linode.com/docs/api/.
"""

from typing import Optional
from urllib.parse import urljoin, quote

import requests
import requests.auth


class LinodeObjectStorageClient:
    """
    Object Storage Client.

    See https://www.linode.com/docs/api/object-storage/.
    """
    LINODE_API = 'https://api.linode.com'

    def __init__(self, token: str):
        self.http = requests.Session()
        self.http.auth = BearerAuth(token)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.http.close()

    def buckets(self):
        r = self.http.get(urljoin(self.LINODE_API, 'v4/object-storage/buckets/'))
        r.raise_for_status()

        # FIXME: Implement pagination
        response = r.json()
        return response['data']

    def create_object_url(self, cluster: str, bucket: str, name: str, method: str = 'GET',
                          content_type: Optional[str] = None, expires_in: Optional[int] = None):
        data = {'name': name, 'method': method}

        if content_type:
            data['content_type'] = content_type

        if expires_in:
            data['expires_in'] = expires_in

        url = urljoin(self.LINODE_API, f'v4/object-storage/buckets/{quote(cluster)}/{quote(bucket)}/object-url')
        r = self.http.post(url, json=data)
        r.raise_for_status()

        response = r.json()
        return response['url']

    def update_object_acl(self, cluster: str, bucket: str, name: str, acl: str):
        data = {'name': name, 'acl': acl}

        url = urljoin(self.LINODE_API, f'https://api.linode.com/v4/object-storage/buckets/{quote(cluster)}/{quote(bucket)}/object-acl')
        r = self.http.put(url, json=data)
        r.raise_for_status()

        response = r.json()
        return response

    def delete_ssl(self, cluster: str, bucket: str):
        url = urljoin(self.LINODE_API, f'https://api.linode.com/v4/object-storage/buckets/{quote(cluster)}/{quote(bucket)}/ssl')
        r = self.http.delete(url)
        r.raise_for_status()

    def create_ssl(self, cluster: str, bucket: str, certificate: str, private_key: str):
        data = {'certificate': certificate, 'private_key': private_key}

        url = urljoin(self.LINODE_API, f'https://api.linode.com/v4/object-storage/buckets/{quote(cluster)}/{quote(bucket)}/ssl')
        r = self.http.post(url, json=data)
        r.raise_for_status()


class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers['Authorization'] = f'Bearer {self.token}'
        return r
