#!/usr/bin/env python
import sys

import cpapi
import json
from cpservers import Servers

class ServerGroups:
    def __init__(self, obj):
        if 'name' in obj:
            self.name = obj['name']
        else:
            self.name = None
        if 'id' in obj:
            self.id = obj['id']
        else:
            self.id = None
        if 'tag' in obj:
            self.tag = obj['tag']
        else:
            self.tag = None
        if 'linux_firewall_policy_id' in obj:
            self.linux_firewall_policy_id = obj['linux_firewall_policy_id']
        else:
            self.linux_firewall_policy_id = None
        if 'windows_firewall_policy_id' in obj:
            self.windows_firewall_policy_id = obj['windows_firewall_policy_id']
        else:
            self.windows_firewall_policy_id = None

    @staticmethod
    def all(apiCon):
        groupList = []
        (response, authError) = apiCon.getServerGroupList()
        if ('groups' in response):
            for obj in response['groups']:
                group = ServerGroups(obj)
                groupList.append(group)
        return groupList

    def memberServers(self,apiCon):
        serverList = []
        (response, authError) = apiCon.getServersInGroup(self.id)
        if ('servers' in response):
            for obj in response['servers']:
                server = Servers(obj)
                serverList.append(server)
        return serverList

    def to_s(self):
        return "Group=%s tag=%s ID=%s" % (self.name, self.tag, self.id)
