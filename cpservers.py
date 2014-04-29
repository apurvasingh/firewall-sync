#!/usr/bin/env python
import sys

import cpapi
import json

class Servers:
    def __init__(self, obj):
        if 'hostname' in obj:
            self.hostname = obj['hostname']
        else:
            self.hostname = None
        if 'id' in obj:
            self.id = obj['id']
        else:
            self.id = None
        if 'state' in obj:
            self.state = obj['state']
        else:
            self.state = None
        if 'connecting_ip_address' in obj:
            self.address = obj['connecting_ip_address']
        else:
            self.address = None

    @staticmethod
    def all(apiCon):
        serverList = []
        (response, authError) = apiCon.getServerList()
        if ('servers' in response):
            for obj in response['servers']:
                server = Servers(obj)
                serverList.append(server)
        return serverList

    def to_s(self):
        return "Server=%s IP=%s ID=%s" % (self.hostname, self.address, self.id)
