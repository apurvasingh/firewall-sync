#!/usr/bin/env python
import sys

import cpapi
import json

class FirewallPolicies:
    def __init__(self, obj):
        if 'name' in obj:
            self.name = obj['name']
        else:
            self.name = None
        if 'id' in obj:
            self.id = obj['id']
        else:
            self.id = None
        if 'platform' in obj:
            self.platform = obj['platform']
        else:
            self.platform = None
        if 'description' in obj:
            self.description = obj['description']
        else:
            self.description = None
        if 'firewall_rules' in obj:
            self.rules = obj['firewall_rules']
        else:
            self.rules = []

    @staticmethod
    def all(apiCon):
        policyList = []
        (response, authError) = apiCon.getFirewallPolicyList()
        if ('firewall_policies' in response):
            for obj in response['firewall_policies']:
                policy = FirewallPolicies(obj)
                policyList.append(policy)
        return policyList

    @staticmethod
    def byId(apiCon,id):
        policy = None
        (response, authError) = apiCon.getFirewallPolicyDetails(id)
        if ('firewall_policy' in response):
            obj = response['firewall_policy']
            policy = FirewallPolicies(obj)
        return policy

    def to_s(self):
        return "FirewallPolicy=%s platform=%s ID=%s" % (self.name, self.platform, self.id)
