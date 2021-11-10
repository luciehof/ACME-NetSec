from dnslib.server import DNSServer
from flask import Flask
from multiprocessing import Process
from flask import request


class ShutdownServer(Process):
    def __init__(self, record_address):
        super().__init__()
        self.app = Flask(__name__)
        self.record_address = record_address

    def run(self):
        @self.app.route('/shutdown')
        def shutdown():
            print("Shutting down acme application...")
            request.environ.get('werkzeug.server.shutdown')
            return "Server shutting down..."

        self.app.run(host=self.record_address, port=5003)
