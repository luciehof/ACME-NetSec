from flask import Flask
from multiprocessing import Process


class HttpServer(Process):
    def __init__(self, token, key_authorization, record_address):
        super().__init__()
        self.token = token
        self.key_authorization = key_authorization
        self.record_address = record_address
        self.app = Flask(__name__)


    def run(self):
        @self.app.route('/.well-known/acme-challenge/' + self.token)
        def challenge():
            #print('HTTP SERVER: ', self.key_authorization)
            return self.key_authorization
        self.app.run(host=self.record_address, port=5002)

