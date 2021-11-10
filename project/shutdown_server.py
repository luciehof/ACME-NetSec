from dnslib.server import DNSServer
from flask import Flask
from multiprocessing import Process
from flask import request


class ShutdownServer(Process):
    def __init__(self, record_address, https_server: Process, dns_server: DNSServer):
        super().__init__()
        self.app = Flask(__name__)
        self.record_address = record_address
        self.https_server = https_server
        self.dns_server = dns_server

    def run(self):
        @self.app.route('/shutdown')
        def shutdown():
            print("Shutting down acme application...")
            if self.https_server is not None and self.dns_server is not None:
                self.https_server.terminate()
                self.https_server.join()
                self.dns_server.stop()
            request.environ.get('werkzeug.server.shutdown')
            return "Server shutting down..."

        self.app.run(host=self.record_address, port=5003)
