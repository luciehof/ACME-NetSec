from flask import Flask
from multiprocessing import Process


class HttpsServer(Process):
    def __init__(self, record_address, certificate: str):
        super().__init__()
        self.app = Flask(__name__)
        self.record_address = record_address
        self.certificate = certificate

    def run(self):
        @self.app.route('/')
        def certificate():
            return self.certificate
        self.app.run(host=self.record_address, port=5001, ssl_context= ("certificate.pem", "cert_pk.pem"))