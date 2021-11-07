import base64
import math
import sys
from typing import List

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils, rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
import json

##
# JSON Object Signing and Encryption implemented with ECDSA algorithm.
##
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509 import NameOID


def base64_encode(b):
    return base64.urlsafe_b64encode(b).decode('utf-8').replace('=', '')


def generate_ecdsa_pk():
    """Generate ECDSA private key and return it."""
    # source: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/
    return ec.generate_private_key(ec.SECP256R1(), default_backend())


def json_web_token(header, payload, pk: EllipticCurvePrivateKey):
    """Return a json a signed JWT."""
    if payload == "":
        base64url_payload = ""
    else:
        json_payload = json.dumps(payload).encode('utf-8')
        base64url_payload = base64_encode(json_payload)

    json_header = json.dumps(header).encode('utf-8')
    base64url_header = base64_encode(json_header)

    signing_input = base64url_header + '.' + base64url_payload
    utf8_signature = pk.sign(signing_input.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
    PK = pk.public_key()
    assert PK.verify(utf8_signature, signing_input.encode('utf-8'), ec.ECDSA(hashes.SHA256())) == None
    r, s = decode_dss_signature(utf8_signature)
    r_bytes = r.to_bytes(math.ceil(r.bit_length() / 8), 'big')
    s_bytes = s.to_bytes(math.ceil(s.bit_length() / 8), 'big')
    base64url_signature = base64_encode(r_bytes + s_bytes)

    jwt_dict = {"protected": base64url_header,
                "payload": base64url_payload,
                "signature": base64url_signature}

    return json.dumps(jwt_dict).encode("utf8")  # signing_input + '.' + base64url_signature


def get_header(nonce: str, url: str, jwk: dict = None, kid: str = None):
    """Return JWS protected header as a dict.
    Must include alg + nonce + url + jwk or kid fields. """
    if kid == None:
        return {'alg': "ES256", 'nonce': nonce, 'url': url, 'jwk': jwk}
    else:
        return {'alg': "ES256", 'nonce': nonce, 'url': url, 'kid': kid}


def get_csr(domains: List):
    cert_pk = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2048)
    with open("cert_pk.pem", "wb") as f:
        f.write(cert_pk.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
                                      encryption_algorithm=serialization.NoEncryption()))
        f.close()

    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]), critical=False)
    csr = csr_builder.sign(cert_pk, hashes.SHA256(), default_backend())
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    csr_b64 = base64_encode(csr_der)
    return csr_b64


def write_pem_cert(certificate: str):
    with open("certificate.pem", 'w') as f:
        f.write(certificate)
        f.close()


def cert_der(certificate):
    cert_enc = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
    cert_der = cert_enc.public_bytes(serialization.Encoding.DER)
    return cert_der