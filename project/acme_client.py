import base64
import enum
import hashlib
import json
import math
import sys
import time
from typing import List
import requests
from dnslib.server import DNSServer

import jose
from dns import DNS
from http_challenge import HttpServer
from jose import base64_encode

from multiprocessing import Process


class Challenge(enum.Enum):
    http = 1
    dns = 2


class AcmeClient:
    def __init__(self, acme_server_url: str, domains: List[str], challenge_type: Challenge, record_address):
        self.acme_server_url = acme_server_url
        self.domains = domains
        self.challenge_type = challenge_type
        self.record_address = record_address
        self.get_server_directory()
        self.get_new_nonce()

    def get_server_directory(self):
        """ Get all URLs corresponding to acme operations (e.g. new account, new nonce) wrt to the acme server url."""
        r = requests.get(self.acme_server_url, verify='pebble.minica.pem')
        self.check_code_status(r)
        r_json = r.json()
        self.new_nonce_url = self.get_url(r_json, "newNonce")
        self.new_account_url = self.get_url(r_json, "newAccount")
        self.new_order_url = self.get_url(r_json, "newOrder")
        self.rev_cert_url = self.get_url(r_json, "revokeCert")
        self.key_change_url = self.get_url(r_json, "keyChange")

    def get_url(self, r_json, key):

        try:
            return r_json[key]
        except KeyError:
            print("No " + key + " key found in json.")

    def get_new_nonce(self):
        """Get and return new nonce value from ACME server."""
        r = requests.head(self.new_nonce_url, verify='pebble.minica.pem')
        self.check_code_status(r)
        self.nonce = r.headers.get("Replay-Nonce")

    def check_code_status(self, r):
        """ Return if HTTP status code is OK, throw an exception otherwise."""
        if r.status_code == requests.codes.ok:
            return
        else:
            r.raise_for_status()

    def server_setup(self):
        """Request an account with the ACME server.
        The client generates asymmetric key pair to sign the account
        creation request to prove it controls this request."""

        # generate asymmetric key pair and get public x,y coordinates
        self.pk = jose.generate_ecdsa_pk()
        x = self.pk.public_key().public_numbers().x
        y = self.pk.public_key().public_numbers().y
        x_bytes = x.to_bytes(math.ceil(x.bit_length() / 8), 'big')
        y_bytes = y.to_bytes(math.ceil(y.bit_length() / 8), 'big')
        str_x = base64_encode(x_bytes)
        str_y = base64_encode(y_bytes)
        # send POST request to server's newAccount URL
        payload = {"termsOfServiceAgreed": True}
        self.jwk_dict = {"crv": 'P-256', "kty": 'EC', "x": str_x, "y": str_y}
        jose_header = jose.get_header(self.nonce, self.new_account_url, jwk=self.jwk_dict)
        jwt = jose.json_web_token(jose_header, payload, self.pk)
        r = requests.post(url=self.new_account_url, headers={"Content-Type": "application/jose+json"}, data=jwt,
                          verify='pebble.minica.pem')
        self.check_code_status(r)
        self.kid = r.headers.get("Location")
        self.nonce = r.headers.get("Replay-Nonce")

    def get_key_authorization(self, token, jwk: dict):
        """For challenge validation, returns keyAuthorization = token || '.' || base64url(Thumbprint(accountKey))"""
        # remove whitespace and line breaks from jwk
        jwk_json = json.dumps(jwk)
        jwk_compact = jwk_json.replace(' ', '').replace('\n', '').encode('utf-8')
        h = hashlib.sha256()
        h.update(jwk_compact)
        return token + '.' + base64_encode(h.digest())

    def dns_challenge(self):
        for c in self.challenges:
            key_authorization = self.get_key_authorization(c['token'], self.jwk_dict)
            # making challenge
            TTL = 300  # TODO: dns periodical record update set to 5min (large upper bound)
            key_hash = hashlib.sha256()
            key_hash.update(key_authorization.encode('utf-8'))
            base64_digest = base64_encode(key_hash.digest())
            zone = " " + str(TTL) + " IN TXT " + base64_digest
            dns = DNS(zone, self.domains)
            dns_server = DNSServer(dns, self.record_address, port=10053)
            dns_server.start_thread()

            # validation request
            jose_header = jose.get_header(self.nonce, c['chal_url'], kid=self.kid)
            jwt = jose.json_web_token(jose_header, {}, self.pk)
            r = requests.post(url=c['chal_url'], headers={"Content-Type": "application/jose+json"}, data=jwt,
                              verify='pebble.minica.pem')
            self.check_code_status(r)
            self.nonce = r.headers.get("Replay-Nonce")

            # server polling
            self.polling(c['auth_url'], "")

            # stop dns server
            dns_server.stop()

    def http_challenge(self):
        """ For all http challenges, make it and validate it."""
        for c in self.challenges:
            key_authorization = self.get_key_authorization(c['token'], self.jwk_dict)
            # making challenge
            http_server = HttpServer(c['token'], key_authorization, self.record_address)
            http_server.start()
            TTL = 300  # dns periodical record update set to 5min (large upper bound)
            zone = " " + str(TTL) + " IN A " + self.record_address
            dns = DNS(zone, self.domains)
            dns_server = DNSServer(dns, self.record_address, port=10053)
            dns_server.start_thread()

            # validation request
            jose_header = jose.get_header(self.nonce, c['chal_url'], kid=self.kid)
            jwt = jose.json_web_token(jose_header, {}, self.pk)
            r = requests.post(url=c['chal_url'], headers={"Content-Type": "application/jose+json"}, data=jwt,
                              verify='pebble.minica.pem')
            self.check_code_status(r)
            self.nonce = r.headers.get("Replay-Nonce")

            # server polling
            self.polling(c['auth_url'], "")

            # stop dns and http servers
            http_server.terminate()
            http_server.join()
            dns_server.stop()

    def polling(self, url, payload):
        status = "invalid"
        while status != "valid":
            jose_header = jose.get_header(self.nonce, url, kid=self.kid)
            jwt = jose.json_web_token(jose_header, payload, self.pk)
            r = requests.post(url=url, headers={"Content-Type": "application/jose+json"}, data=jwt,
                              verify='pebble.minica.pem')

            self.check_code_status(r)
            self.nonce = r.headers.get("Replay-Nonce")
            r_json = r.json()
            status = r_json["status"]
            if status == "invalid":
                print("POLLING: invalid validation status")  # TODO: handle invalid status
                break
            time.sleep(3)  # sleep for 3 secs before polling again
        return r_json

    def get_challenges(self):
        """Get challenge from the server to prove control of the domain
                for which the certificate is ordered."""
        payload = ""
        self.challenges = []
        for url in self.authorizations_url:
            jose_header = jose.get_header(self.nonce, url, kid=self.kid)
            jwt = jose.json_web_token(jose_header, payload, self.pk)
            r = requests.post(url=url, headers={"Content-Type": "application/jose+json"}, data=jwt,
                              verify='pebble.minica.pem')

            self.check_code_status(r)
            self.nonce = r.headers.get("Replay-Nonce")
            r_json = r.json()
            if self.challenge_type == Challenge.http:
                for challenge in r_json["challenges"]:
                    if challenge["type"] == "http-01":
                        c = {'auth_url': url, 'chal_url': challenge["url"],
                             'token': challenge["token"]}
            else:
                for challenge in r_json["challenges"]:
                    if challenge["type"] == "dns-01":
                        c = {'auth_url': url, 'chal_url': challenge["url"],
                             'token': challenge["token"]}
            self.challenges.append(c)

    def validate_challenges(self):
        self.get_challenges()
        if self.challenge_type == Challenge.http:
            self.http_challenge()
        else:
            self.dns_challenge()

    def order_certificate(self):
        """Submit an order for a certificate to be issued by the server."""

        payload = {"identifiers": [{"type": "dns", "value": d} for d in self.domains]}
        jose_header = jose.get_header(self.nonce, self.new_order_url, kid=self.kid)
        jwt = jose.json_web_token(jose_header, payload, self.pk)
        r = requests.post(url=self.new_order_url, headers={"Content-Type": "application/jose+json"}, data=jwt,
                          verify='pebble.minica.pem')
        self.check_code_status(r)
        self.nonce = r.headers.get("Replay-Nonce")
        r_json = r.json()
        self.authorizations_url = r_json["authorizations"]
        self.finalize_url = r_json["finalize"]
        self.order_url = r.headers.get("Location")

    def finalize_certificate(self):
        """Finalize certificate order after challenge validation by
               sending a Certificate Signing Request.
               The server then makes the certificate available to the client,
               that can download it."""
        csr = jose.get_csr(self.domains)
        payload = {'csr': csr}
        jose_header = jose.get_header(self.nonce, self.finalize_url, kid=self.kid)
        jwt = jose.json_web_token(jose_header, payload, self.pk)
        r = requests.post(url=self.finalize_url, headers={"Content-Type": "application/jose+json"}, data=jwt,
                          verify='pebble.minica.pem')

        self.check_code_status(r)
        self.nonce = r.headers.get("Replay-Nonce")
        r_json = self.polling(self.order_url, "")
        self.cert_url = r_json["certificate"]

    def download_certificate(self):
        """Download the certificate from the server and install it on the
        HTTPS server."""
        payload = ""
        jose_header = jose.get_header(self.nonce, self.cert_url, kid=self.kid)
        jwt = jose.json_web_token(jose_header, payload, self.pk)
        r = requests.post(url=self.cert_url, headers={"Content-Type": "application/jose+json"}, data=jwt,
                          verify='pebble.minica.pem')
        self.check_code_status(r)
        self.nonce = r.headers.get("Replay-Nonce")
        self.certificate = r.text
        jose.write_pem_cert(self.certificate)
        return self.certificate
