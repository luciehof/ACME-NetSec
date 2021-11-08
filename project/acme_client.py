import enum
import hashlib
import math
import time
from typing import List
import requests
from dnslib.server import DNSServer

import jose
from dns import DNS
from http_challenge import HttpServer
from jose import base64_encode, get_key_authorization


class Challenge(enum.Enum):
    http = 1
    dns = 2


def check_code_status(r):
    """ Return if HTTP status code is OK, throw an exception otherwise."""
    if r.status_code == requests.codes.ok:
        return
    else:
        r.raise_for_status()


def get_url(r_json, key):
    try:
        return r_json[key]
    except KeyError:
        print("No " + key + " key found in json.")


class AcmeClient:
    def __init__(self, acme_server_url: str, domains: List[str], challenge_type: Challenge, record_address,
                 revoke=False):
        self.revoke = revoke
        self.acme_server_url = acme_server_url
        self.domains = domains
        self.challenge_type = challenge_type
        self.record_address = record_address
        self.new_nonce_url = None
        self.new_account_url = None
        self.new_order_url = None
        self.rev_cert_url = None
        self.authorizations_url = None
        self.finalize_url = None
        self.order_url = None
        self.cert_url = None
        self.server_certificate_validity = self.get_server_directory()
        self.nonce = None
        self.jwk_dict = None
        self.kid = None
        self.default_dns_zone = ""
        self.challenges = []
        self.pk = None
        self.certificate = None
        if self.server_certificate_validity == 0:
            self.get_new_nonce()
            self.dns_server = self.launch_default_dns()

    def launch_default_dns(self):
        TTL = 300  # dns periodical record update set to 5min (large upper bound)
        self.default_dns_zone = " " + str(TTL) + " IN A " + self.record_address
        return self.launch_dns([self.default_dns_zone])

    def launch_dns(self, zones):
        dns = DNS(zones, self.domains)
        dns_server = DNSServer(dns, self.record_address, port=10053)
        dns_server.start_thread()
        return dns_server

    def get_server_directory(self) -> int:
        """ Get all URLs corresponding to acme operations (e.g. new account, new nonce) wrt to the acme server url."""
        try:
            r = requests.get(self.acme_server_url, verify='pebble.minica.pem')
        except requests.exceptions.SSLError:
            print("SSLError: certificate verify failed.")
            return 1
        check_code_status(r)
        r_json = r.json()
        self.new_nonce_url = get_url(r_json, "newNonce")
        self.new_account_url = get_url(r_json, "newAccount")
        self.new_order_url = get_url(r_json, "newOrder")
        self.rev_cert_url = get_url(r_json, "revokeCert")
        return 0

    def get_new_nonce(self):
        """Get and return new nonce value from ACME server."""
        r = requests.head(self.new_nonce_url, verify='pebble.minica.pem')
        check_code_status(r)
        self.nonce = r.headers.get("Replay-Nonce")

    def server_setup(self) -> int:
        """Request an account with the ACME server.
        The client generates asymmetric key pair to sign the account
        creation request to prove it controls this request."""

        if self.server_certificate_validity == 1:
            return 1

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
        r = self.acme_server_post_request(payload, self.new_account_url, jwk=self.jwk_dict)
        self.kid = r.headers.get("Location")

        return 0

    def acme_server_post_request(self, payload, url, print_debug=False, jwk=None, kid=None):  # TODO: remove debug param
        jose_header = jose.get_header(self.nonce, url, jwk=jwk, kid=kid)
        jwt = jose.json_web_token(jose_header, payload, self.pk)
        r = requests.post(url=url, headers={"Content-Type": "application/jose+json"}, data=jwt,
                          verify='pebble.minica.pem')
        if print_debug:
            print("jose_header: ", jose_header)
            print("jwt: ", jwt)
            print("r: ", r.text)
        check_code_status(r)
        self.nonce = r.headers.get("Replay-Nonce")
        return r

    def dns_challenge(self):
        self.dns_server.stop()
        for c in self.challenges:
            key_authorization = get_key_authorization(c['token'], self.jwk_dict)
            # making challenge
            TTL = 300
            key_hash = hashlib.sha256()
            key_hash.update(key_authorization.encode('utf-8'))
            base64_digest = base64_encode(key_hash.digest())
            zone = " " + str(TTL) + " IN TXT " + base64_digest
            challenge_dns_server = self.launch_dns([zone, self.default_dns_zone])

            # validation request
            self.acme_server_post_request({}, c['chal_url'], kid=self.kid)

            # server polling
            self.polling(c['auth_url'], "")

            # stop dns server for dns challenge, restart default one
            challenge_dns_server.stop()
        self.dns_server.start_thread()

    def http_challenge(self):
        """ For all http challenges, make it and validate it."""
        for c in self.challenges:
            key_authorization = get_key_authorization(c['token'], self.jwk_dict)
            # making challenge
            http_server = HttpServer(c['token'], key_authorization, self.record_address)
            http_server.start()

            # validation request
            self.acme_server_post_request({}, c['chal_url'], kid=self.kid)

            # server polling
            self.polling(c['auth_url'], "")

            # stop dns and http servers
            http_server.terminate()
            http_server.join()

    def polling(self, url, payload):
        status = ""
        while status != "valid":
            r = self.acme_server_post_request(payload, url, kid=self.kid)
            r_json = r.json()
            status = r_json["status"]
            if status == "invalid":
                print("POLLING: invalid validation status")
                break
            time.sleep(3)  # sleep for 3 secs before polling again
        return r_json

    def get_challenges(self):
        """Get challenge from the server to prove control of the domain
                for which the certificate is ordered."""
        payload = ""
        for url in self.authorizations_url:
            r = self.acme_server_post_request(payload, url, kid=self.kid)
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
        r = self.acme_server_post_request(payload, self.new_order_url, kid=self.kid)
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
        self.acme_server_post_request(payload, self.finalize_url, kid=self.kid)
        r_json = self.polling(self.order_url, "")
        self.cert_url = r_json["certificate"]

    def download_certificate(self):
        """Download the certificate from the server and install it on the
        HTTPS server."""
        payload = ""
        r = self.acme_server_post_request(payload, self.cert_url, kid=self.kid)
        self.certificate = r.text
        jose.write_pem_cert(self.certificate)
        if self.revoke:
            self.revoke_certificate(self.certificate)
        return self.certificate

    def revoke_certificate(self, certificate):
        cert_der = base64_encode(jose.cert_der(certificate))
        payload = {"certificate": cert_der}
        self.acme_server_post_request(payload, self.rev_cert_url, kid=self.kid)
