#!/usr/bin/env python3

import argparse
import base64
import csv
import io
import json
import logging
import secrets
import subprocess
import sys
import time

from urllib.request import Request, urlopen
from urllib.error import HTTPError

HOST_PREFIX = '_acme-challenge'
TIMEOUT_S = 60


def find_root_authority(domain):
    """
    Finds the root authority/NS and root domain for a domain name.

    For example, for www3.example.co.uk it would return (ns0.transip.net., example.co.uk).

    It keeps removing prefixes and makes SOA requests until there's a hit.
    """
    parts = domain.split('.')
    while len(parts) > 1:
        root = '.'.join(parts)
        soa = dig(root, 'SOA')
        if soa is not None:
            return (soa, root)
        parts = parts[1:]
    return None


def dig(name, rtype, server=None):
    """ Does a DNS lookup using `dig`. """
    cmd = ["dig"]
    if server:
        cmd.append(f"@{server}")
    cmd.append(name)
    cmd.append(rtype)
    cmd.append("+short")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output, _err = proc.communicate()
    for rec in csv.reader(io.StringIO(output.decode('ascii')),
                          delimiter=' '):
        return rec[0]
    return None


class TransipClient:
    """
    Simple REST-client for Transip, supporting authentication, creating and
    removing of TXT DNS records.
    """

    API_HOST = 'https://api.transip.nl'

    AUTH_URL = API_HOST + '/v6/auth'
    DNS_URL = API_HOST + '/v6/domains/%s/dns'

    def __init__(self, username=None, keyfile=None, token=None):
        if token is None and (username is None or keyfile is None):
            raise ValueError("No token, username or keyfile provided")

        self._username = username
        self._keyfile = keyfile
        self._token = token
        self._logger = logging.getLogger()

    def _signature(self, request):
        json_req = json.dumps(request).encode()
        proc = subprocess.Popen(["openssl", "dgst", "-sha512", "-sign", self._keyfile],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        sig, _err = proc.communicate(input=json_req)
        return base64.b64encode(sig)

    def _get_auth_headers(self):
        if self._token is None:
            self._token = self._get_token()
            # Print JWT token to stdout so it can be captured for later use.
            print("JWT: %s" % self._token)
        return {
            'Authorization': 'Bearer %s' % self._token
        }

    def _get_token(self):
        self._logger.info("Authenticating.")
        request = {
            "login": self._username,
            "nonce": secrets.token_urlsafe()[:32],
            "read_only": False,
            "expiration_time": "30 minutes",
            "global_key": False,
        }
        headers = {
            'Signature': self._signature(request)
        }
        return self._rest_call('POST', self.AUTH_URL,
                               request, headers)['token']

    def _rest_call(self, method, url, body=None, extra_headers=None):
        json_req = json.dumps(body).encode()
        headers = {
                      'Content-Type': 'application/json; charset=UTF-8',
                      'Accept': 'application/json',
                  } | (extra_headers if extra_headers is not None else {})

        request = Request(url, data=json_req, headers=headers, method=method)
        try:
            with urlopen(request) as response:
                if response.status == 204:
                    return None
                return json.loads(response.read().decode(
                    response.headers.get_content_charset('utf-8')))
        except HTTPError as e:
            self._logger.error(e.fp.read())
            raise

    def _get_txt_record(self, domain, name):
        resp = self._rest_call(
            'GET', self.DNS_URL % domain,
            extra_headers=self._get_auth_headers())
        try:
            return next(entry
                        for entry in resp['dnsEntries']
                        if entry['name'] == name and entry['type'] == 'TXT')
        except StopIteration:
            return None

    def ensure_txt_record(self, domain, name, value):
        existing_record = self._get_txt_record(domain, name)
        if existing_record is None:
            self._logger.info("Creating record for %s.%s" % (name, domain))
        else:
            self._logger.info("Updating record for %s.%s" % (name, domain))

        record = {
            'dnsEntry': {
                'name': name,
                'expire': 60,  # 1 minute is minimum.
                'type': 'TXT',
                'content': value,
            }
        }
        self._rest_call(
            'POST' if existing_record is None else 'PATCH',
            self.DNS_URL % domain,
            body=record, extra_headers=self._get_auth_headers())

    def remove_txt_record(self, domain, name):
        rec = self._get_txt_record(domain, name)
        if rec is not None:
            self._logger.info("Removing record %s.%s" % (name, domain))
            body = {
                'dnsEntry': rec
            }
            self._rest_call(
                'DELETE',
                self.DNS_URL % domain,
                extra_headers=self._get_auth_headers(),
                body=body)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        format='%(levelname)s:%(message)s')

    parser = argparse.ArgumentParser(
        description='Manage TXT records for automatic certbot DNS-01 validation at Transip')
    parser.add_argument('command', choices=('create', 'cleanup'),
                        help='Create a record or clean it up')
    parser.add_argument('domain',
                        help='Domain to validate, e.g. value of CERTBOT_DOMAIN')
    parser.add_argument('--validation',
                        help='Validation string, e.g. value of CERTBOT_VALIDATION')
    parser.add_argument('--username', help='Username at Transip')
    parser.add_argument('--private_keyfile',
                        help='Name of file containing private key for Transip API')
    parser.add_argument('--bearer_token', help='Existing bearer token for Transip')

    args = parser.parse_args()
    if (args.private_keyfile is None or args.username is None) and args.bearer_token is None:
        logging.error(
            "Provide either --bearer_token or --username and --private_keyfile "
            "to authenticate requests to Transip.")
        sys.exit(1)

    if args.command == 'create' and args.validation is None:
        logging.error("Provide --validation to create record")
        sys.exit(1)

    # for hostname.example.co.uk:
    # ns = ns0.transip.net.
    # name = _acme-challenge.hostname
    # domain = example.co.uk
    ns, domain = find_root_authority(args.domain)
    host = args.domain[:-len(domain) - 1]
    name = f'{HOST_PREFIX}.{host}'
    if not ns.endswith('transip.net.'):
        logging.error('Domain is not hosted at TransIP')
        sys.exit(1)

    t = TransipClient(username=args.username, keyfile=args.private_keyfile,
                      token=args.bearer_token)
    if args.command == 'create':
        t.ensure_txt_record(domain, name, args.validation)
        # Wait until record is updated.
        start_time = time.monotonic()
        while start_time + TIMEOUT_S > time.monotonic():
            if dig(f'{name}.{domain}', 'TXT', ns) == args.validation:
                sys.exit(0)
            logging.info('Waiting for TXT record to update...')
            time.sleep(5)
        logging.error("Timeout waiting for DNS record")
        sys.exit(1)

    elif args.command == 'cleanup':
        t.remove_txt_record(domain, name)
