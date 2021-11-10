import os
import sys
import time
from typing import List

from acme_client import AcmeClient, Challenge
from https_server import HttpsServer
from shutdown_server import ShutdownServer

CHALLENGE_TYPE = sys.argv[1]
DOMAINS = []
DIR_URL = ""
IPV4_ADDRESS = ""
REVOKE = False

args = sys.argv[2:]
for i in range(0, len(args), 2):
    if args[i] == "--dir":
        DIR_URL = args[i + 1]
    elif args[i] == "--record":
        IPV4_ADDRESS = args[i + 1]
    elif args[i] == "--domain":
        DOMAINS.append(args[i + 1])
    elif args[i] == "--revoke":
        REVOKE = True

assert type(DIR_URL != str)
print("dir url ", DIR_URL)
assert type(DOMAINS == List[str])
print("domains ", DOMAINS)
assert type(IPV4_ADDRESS != str)
print("record ", IPV4_ADDRESS)

if CHALLENGE_TYPE == 'dns01':
    challenge_type = Challenge.dns
else:
    challenge_type = Challenge.http

https_server = None

acme_client = AcmeClient(DIR_URL, DOMAINS, challenge_type, IPV4_ADDRESS, REVOKE)
print("-----------------------------")
print("Setting up account with Acme server...")
server_certificate_validity = acme_client.server_setup()

if server_certificate_validity == 0:
    print("Server setup done.")
    print("-----------------------------")
    print("Ordering certificate (send CSR)...")
    acme_client.order_certificate()
    print("CSR done.")
    print("-----------------------------")
    print("Validating challenges...")
    acme_client.validate_challenges()  # TODO: validate challenges for each domain name independently???
    print("Challenges done.")
    print("-----------------------------")
    print("Finalizing certificate order...")
    acme_client.finalize_certificate()
    print("Finalization done.")
    print("-----------------------------")
    print("Downloading certificate from server...")
    certificate = acme_client.download_certificate()
    print("Downloading done.")
    print("-----------------------------")
    print("Putting newly obtained certificate on https server...")

    https_server = HttpsServer(IPV4_ADDRESS, certificate)
    https_server.start()

    print("Https server up with new certificate, shutdown server starting...")
else:
    print("Acme server certificate is invalid. Starting shutdown server...")

shutdown_server = ShutdownServer(IPV4_ADDRESS)
shutdown_server.start()

if server_certificate_validity == 0:
    os.wait()#time.sleep(1)
    https_server.terminate()
    https_server.join()
    acme_client.dns_server.stop()
