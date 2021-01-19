# ACME ("Let's Encrypt") client for Linode Object Storage

Automatically provision a [Linode Object Storage](https://www.linode.com/products/object-storage/) bucket
with a [Let's Encrypt](https://letsencrypt.org/) certificate.

## Requirements

Requires [Python 3.8+](https://www.python.org) with [Cryptography](https://github.com/pyca/cryptography)
and [Requests](https://github.com/psf/requests).

```
pip install cryptography requests
```

## Usage

This assumes you have already [created an Object Storage Bucket](https://www.linode.com/docs/guides/enable-ssl-for-object-storage/#create-an-object-storage-bucket)
for a domain (e.g. `my.bucket.domain`) and [configured a DNS](https://www.linode.com/docs/guides/enable-ssl-for-object-storage/#configure-dns)
to point to the bucket.

The bucket name and DNS name **must** be identical.

1. Generate Let's Encrypt account key:

    ```bash
    openssl genrsa 4096 > account_key.pem
    ```

2. Create a Linode API [Personal Access Token](https://cloud.linode.com/profile/tokens)
with Read/Write permission to Object Storage.

3. Provision a certificate for this bucket:

    ```bash
    export LINODE_TOKEN=...
    python3 -m acme_linode_objectstorage -k account_key.pem my.bucket.domain
    ```

    The Object Storage cluster can be specified with the `--cluster` flag (default: `us-east-1`).
    
    If this is the first time running the script, you will also need to include the
    `--agree-to-terms-of-service` flag to indicate agreement with the
    [Let's Encrypt Terms of Service](https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf).


Certificates are typically valid for 90-days. This script should be re-run approximately
30-days prior to certificate expiration.

# License

Licenced under the MIT License. See [LICENSE](LICENSE) for details.


