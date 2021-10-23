import argparse
import contextlib
import logging
import os
import sys
from urllib.parse import quote, urlunsplit

import requests
import requests.auth
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from acme_linode_objectstorage.acme import AcmeClient
from acme_linode_objectstorage.linode import LinodeObjectStorageClient

LINODE_TOKEN = os.environ.get('LINODE_TOKEN')
SUPPORTED_CHALLENGES = {'http-01'}
USER_AGENT = 'acme-linode-objectstorage'
KEY_SIZE = 2048


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', '--account-key', required=True)
    parser.add_argument('-C', '--cluster', default='us-east-1')
    parser.add_argument('--agree-to-terms-of-service', action='store_true')
    parser.add_argument('domain')
    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.DEBUG)

    args = parse_args()

    if LINODE_TOKEN is None:
        print('ERROR: LINODE_TOKEN environment variable not set', file=sys.stderr)
        return 2

    with open(args.account_key, 'rb') as f:
        account_key = serialization.load_pem_private_key(f.read(), None)

    logging.info('Generating %d-bit RSA private key', KEY_SIZE)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)

    logging.info('Creating CSR for %s', args.domain)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, args.domain),
    ])).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(args.domain),
        ]),
        critical=False
    ).sign(private_key, hashes.SHA256())

    with contextlib.ExitStack() as cleanup:
        object_storage = LinodeObjectStorageClient(LINODE_TOKEN)
        cleanup.push(object_storage)

        acme = AcmeClient(account_key)
        cleanup.push(acme)

        object_storage.http.headers['User-Agent'] = USER_AGENT
        acme.http.headers['User-Agent'] = USER_AGENT

        buckets = [bucket for bucket in object_storage.buckets()
                   if bucket['cluster'] == args.cluster and bucket['label'] == args.domain]
        if not buckets:
            print('ERROR: No matching bucket found', file=sys.stderr)
            return 1

        logging.info('Registering account')
        try:
            account = acme.new_account(terms_of_service_agreed=args.agree_to_terms_of_service)
        except requests.HTTPError as e:
            print(f'ERROR: Failed to create account: {e.response.text}', file=sys.stderr)
            return 1

        logging.debug('account: %s', account)

        logging.info('Creating new order for %s', args.domain)
        domains = [args.domain]
        try:
            order = acme.new_order(domains)
        except requests.HTTPError as e:
            print(f'ERROR: Failed to create order: {e.response.text}', file=sys.stderr)
            return 1

        logging.debug('order: %s', order)

        logging.info('Performing authorizations')
        for authorization in order.authorizations:
            for challenge in authorization.challenges:
                if challenge.type in SUPPORTED_CHALLENGES:
                    break
            else:
                print(f'ERROR: No supported challenges', file=sys.stderr)
                return 1

            # Create http-01 challenge resource
            try:
                obj_name = f'/.well-known/acme-challenge/{quote(challenge["token"])}'
                data = f'{challenge["token"]}.{account.key_thumbprint}'

                put_url = object_storage.create_object_url(
                    args.cluster, args.domain, obj_name, 'PUT', 'text/plain', expires_in=360)

                requests.put(put_url, data=data, headers={'Content-Type': 'text/plain'}).raise_for_status()
            except requests.HTTPError as e:
                print(f'ERROR: Failed to create challenge resource: {e.response.text}', file=sys.stderr)
                return 1

            try:
                # Make challenge resource publicly readable
                object_storage.update_object_acl(args.cluster, args.domain, obj_name, 'public-read')

                # Check we can read the challenge resource
                try:
                    requests.head(urlunsplit(('http', args.domain, obj_name, '', ''))).raise_for_status()
                except requests.HTTPError as e:
                    print(f'ERROR: Failed to read challenge: {e}', file=sys.stderr)
                    return 1

                # Respond to the challenge
                try:
                    challenge.respond()
                    challenge.poll_until_not({'processing', 'pending'})
                except requests.HTTPError as e:
                    print(f'ERROR: Responding to challenge failed: {e.response.text}', file=sys.stderr)
                    return 1

                if challenge.status != 'valid':
                    print(f'ERROR: Challenge unsuccessful: {challenge.status}', file=sys.stderr)
                    return 1

            finally:
                # Cleanup challenge resource
                try:
                    delete_url = object_storage.create_object_url(
                        args.cluster, args.domain, obj_name, 'DELETE', expires_in=360)

                    requests.delete(delete_url).raise_for_status()
                except requests.HTTPError as e:
                    logging.warning('Failed to cleanup challenge resource: %s', e)

        logging.info('Finalizing order')
        try:
            order.finalize(csr)
            order.poll_until_not({'processing'})
        except requests.HTTPError as e:
            print(f'ERROR: Failed to finalize order: {e.response.text}', file=sys.stderr)
            return 1

        if order.status != 'valid':
            print(f'ERROR: Finalize unsuccessful: {order.status}', file=sys.stderr)
            return 1

        try:
            certificate = order.certificate()
        except requests.HTTPError as e:
            print(f'ERROR: Failed to fetch certificate: {e.response.text}', file=sys.stderr)
            return 1

        logging.info('Updating certs')
        try:
            object_storage.delete_ssl(args.cluster, args.domain)
        except requests.HTTPError as e:
            print(f'ERROR: Failed to delete old certificate: {e.response.text}', file=sys.stderr)
            return 1

        private_key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()).decode('ascii')

        try:
            object_storage.create_ssl(args.cluster, args.domain, certificate, private_key_pem)
        except requests.HTTPError as e:
            print(f'ERROR: Failed to create certificate: {e.response.text}', file=sys.stderr)
            return 1


if __name__ == '__main__':
    sys.exit(main())
