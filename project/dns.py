""" Depending on whether we are using the http or dns challenge, this dns will be queried for A record or TXT record
respectively. """
from dnslib import RR
from dnslib.server import BaseResolver


class DNS(BaseResolver):
    def __init__(self, zones, domains):
        self.zones = zones  # e.g. corresponds to " TTL IN A 1.2.3.4" in "abc.com TTL IN A 1.2.3.4"
        self.domains = domains

    def resolve(self, request, handler):
        reply = request.reply()
        for d in self.domains:
            for z in self.zones:
                zone = d + z
                reply.add_answer(*RR.fromZone(zone))
        return reply
