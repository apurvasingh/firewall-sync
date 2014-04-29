#!/usr/bin/env python

import os.path
import sys
try:
    import boto
    import boto.ec2
except:
    print >>sys.stderr, "Unable to import boto modules, make sure it's installed"
    sys.exit(1)
try:
    import aws_ec2
except:
    print >>sys.stderr, "Unable to import AwsHalo modules, make sure aws_ec2.py is in your PYTHONPATH"
    sys.exit(1)
try:
    import cpapi
    import cputils
    import cpservers
    import cpgroups
    import cpfwpolicies
except:
    print >>sys.stderr, "Unable to import CPHalo modules, make sure cpapi.py,etc. are in your PYTHONPATH"
    sys.exit(1)

serverIP = None
verbose = False
extraVerbose = False
explainMismatches = False
serverGroupName = None
awsRegionName = None
dryRun = False
authFilename = "sync.auth"
predefinedRules = []

def processCommandLine(args):
    global serverIP, verbose, extraVerbose, serverGroupName, awsRegionName, dryRun, authFilename, explainMismatches
    for arg in args:
        if (arg == "-v") or (arg == "--verbose"):
            if (verbose):
                extraVerbose = True # add a second "-v" for "extra" verbosity
            verbose = True
        elif (arg == "-x"):
            explainMismatches = True
        elif (arg.startswith("--auth=")):
            authFilename = arg.split("=")[1]
        elif (arg.startswith("--region=")):
            awsRegionName = arg.split("=")[1]
        elif (arg.startswith("--group=")):
            serverGroupName = arg.split("=")[1]
        elif (arg == "-h") or (arg == "-?"):
            usage()
            sys.exit(1)
        elif (arg == "--dryrun"):
            dryRun = True
        else:
            serverIP = arg


def usage():
    print >>sys.stderr, "Usage: %s [flags...] <external-ip-of-instance>" % os.path.basename(sys.argv[0])
    print >>sys.stderr, "Where [flags...] is one or more of the following optional flags:"
    print >>sys.stderr, "-v\t\t\tSets verbose mode"
    print >>sys.stderr, "-x\t\t\tExplain mismatches if they occur"
    print >>sys.stderr, "--region=<aws-region>\tSet AWS region containing servers"
    print >>sys.stderr, "--group=<halo-group>\tSet Halo Server Group containing servers"
    print >>sys.stderr, "--auth=<auth-file>\tSet Halo Server Group containing servers"
    print >>sys.stderr, "--dryrun\t\tPrint out what SGs would be assigned but don't do actual changes"


def getHaloConnection(authFilename,progDir):
    if not os.path.exists(authFilename):
        print >> sys.stderr, "Auth file %s does not exist. Exiting..." % authFilename
        sys.exit(1)
    credentials = cputils.processAuthFile(authFilename,progDir)
    credential = credentials[0][0]
    haloConn = cpapi.CPAPI()
    (haloConn.key_id, haloConn.secret) = (credential['id'], credential['secret'])
    if ((not haloConn.key_id) or (not haloConn.secret)):
        print >> sys.stderr, "Unable to read auth file %s. Exiting..." % authFilename
        print >> sys.stderr, "Requires lines of the form \"<API-id>|<secret>\""
        sys.exit(1)
    resp = haloConn.authenticateClient()
    if (not resp):
        # no error message here, rely on cpapi.authenticate client for error message
        sys.exit(1)
    return haloConn


def findGroupContainingServerByIP(apiCon, externalIP, groupName):
    groupList = cpgroups.ServerGroups.all(apiCon)
    if (groupList != None):
        for group in groupList:
            if (groupName != None) and (groupName.lower() != group.name.lower()):
                continue
            serverList = group.memberServers(apiCon)
            if (serverList != None):
                for server in serverList:
                    if (externalIP == server.address) or (externalIP.lower() == server.hostname.lower()):
                        return group
                    elif (verbose):
                        print "Server: %s -> %s" % (server.hostname, server.address)
    return None


def findInstanceByIP(conn,serverIP):
    serverIP = serverIP.lower()
    reservations = conn.get_all_instances()
    for reservation in reservations:
        for instance in reservation.instances:
            if (serverIP == instance.ip_address) or (serverIP == instance.dns_name.lower()):
                return (reservation, instance)
            if (serverIP == instance.public_dns_name.lower()) or (serverIP == instance.private_dns_name.lower()):
                return (reservation, instance)
            if (instance.public_dns_name != None):
                if (serverIP == instance.public_dns_name.lower()):
                    return (reservation, instance)
                publicDNS = instance.public_dns_name.split('.')[0].lower()
                if (serverIP == publicDNS):
                    return (reservation, instance)
            if (instance.private_dns_name != None):
                if (serverIP == instance.private_dns_name.lower()):
                    return (reservation, instance)
                privateDNS = instance.private_dns_name.split('.')[0].lower()
                if (serverIP == privateDNS):
                    return (reservation, instance)
    return (None, None)


def dumpFirewallSource(fwsrc):
    print "    source: %s type=%s ip=%s" % (fwsrc['name'], fwsrc['type'], fwsrc['ip_address'])

def dumpFirewallInterface(fwif):
    print "    interface: %s" % fwif['name']

def dumpFirewallTarget(fwtarget):
    print "    target: %s" % fwtarget['name']

def dumpFirewallService(fwsvc):
    print "    service: %s %s/%s" % (fwsvc['name'], fwsvc['port'], fwsvc['protocol'])

def dumpFirewallRule(rule):
    print "  Rule: %s, %s, %s" % (rule['chain'], rule['connection_states'], rule['action'])
    if ('firewall_source' in rule):
        dumpFirewallSource(rule['firewall_source'])
    if ('firewall_interface' in rule):
        dumpFirewallInterface(rule['firewall_interface'])
    if ('firewall_target' in rule):
        dumpFirewallTarget(rule['firewall_target'])
    if ('firewall_service' in rule):
        dumpFirewallService(rule['firewall_service'])

def dumpFirewallPolicy(fwp):
    print "Firewall Policy: %s [%s]" % (fwp.name, fwp.platform)
    for rule in fwp.rules:
        dumpFirewallRule(rule)


def matchRuleDirection(chain,inbound):
    if (chain.lower() == "input") and (inbound == False):
        return False
    if (chain.lower() == "output") and (inbound == True):
        return False
    return True


def matchRuleSource(fwsrc,grants):
    if (fwsrc == None):
        if (grants == None) or (len(grants) == 0):
            return True
        else:
            for grant in grants:
                if (grant.cidr_ip != None) and (grant.cidr_ip != "0.0.0.0/0"):
                    return False
            return True
    else:
        if (fwsrc['type'] == "FirewallZone"):
            if ((grants == None) or (len(grants) == 0)) and (fwsrc['ip_address'] != "0.0.0.0/0"):
                return False
            for grant in grants:
                if (grant.cidr_ip == None): # comparing IP-based FW Source to non-IP-based Grant.. not valid
                    return False
                if (grant.cidr_ip != None) and (grant.cidr_ip != fwsrc['ip_address']):
                    return False
            return True
        else:
            return True


def matchHaloRuleToSG(rule,groups,prefix):
    if ('firewall_service' in rule):
        fwsvc = rule['firewall_service']
        (port, protocol) = (fwsvc['port'], fwsvc['protocol'].lower())
        for group in groups:
            if (prefix != None) and (not group.name.startswith(prefix)):
                # print "No match: %s does not begin with %s" % (group.name, prefix)
                continue
            for sgrule in group.rules:
                if (not matchRuleDirection(rule['chain'],sgrule.inbound)):
                    continue
                fwsrc = None
                if ('firewall_source' in rule):
                    fwsrc = rule['firewall_source']
                if (not matchRuleSource(fwsrc,sgrule.grants)):
                    continue
                if (port == sgrule.from_port) and (port == sgrule.to_port) and (protocol == sgrule.ip_protocol):
                    print "Matching SG: %s" % group.name
                    return group
    return None


def sgMatchFirewallSource(rule,grant):
    if (grant.cidr_ip == None) or (grant.cidr_ip == "0.0.0.0/0"):
        # grant is wildcard, match wildcard (or empty) FW zone
        if ('firewall_source' in rule):
            fwsrc = rule['firewall_source']
            if (fwsrc['type'] == "FirewallZone") and (fwsrc['ip_address'] == "0.0.0.0/0"):
                return True
        else:
            return True
    else:
        if ('firewall_source' in rule):
            fwsrc = rule['firewall_source']
            if (fwsrc['type'] == "FirewallZone") and (fwsrc['ip_address'] == grant.cidr_ip):
                return True
    return False


def sgMatchFirewallService(rule,sgRule):
    if ('firewall_service' in rule):
        fwsvc = rule['firewall_service']
        protocol = fwsvc['protocol'].lower()
        port = int(fwsvc['port'])
        from_port = int(sgRule.from_port)
        to_port = int(sgRule.to_port)
        if (protocol == sgRule.ip_protocol.lower()) and (port == from_port) and (port == to_port):
            return True
    return False


def sgMatchHaloRule(sgRule,grant,ruleList,explain):
    matched = False
    for rule in ruleList:
        if (explain):
            print "Attempting to match rule:"
            dumpFirewallRule(rule)
        if (not matchRuleDirection(rule['chain'],sgRule.inbound)):
            if (explain):
                print "Did not match direction: chain=%s sg.inbound=%s" % (rule['chain'],str(sgRule.inbound))
            continue
        if (not sgMatchFirewallSource(rule,grant)):
            if (explain):
                print "Did not match source"
            continue
        if (not sgMatchFirewallService(rule,sgRule)):
            if (explain):
                print "Did not match service"
            continue
        matched = True
    return matched


def sgMatchesHaloFWP(sg,ruleList,prefix):
    if (prefix != None) and (not sg.name.startswith(prefix)):
        return False
    for sgRule in sg.rules:
        for grant in sgRule.grants:
            matched = False
            for rule in ruleList:
                if (not matchRuleDirection(rule['chain'],sgRule.inbound)):
                    continue
                if (not sgMatchFirewallSource(rule,grant)):
                    continue
                if (not sgMatchFirewallService(rule,sgRule)):
                    continue
                matched = True
            if not sgMatchHaloRule(sgRule,grant,ruleList,False):
                if (explainMismatches):
                    print "SG %s did not match: %s | %s" % (sg.name, sgRule.to_short_s(), grant.to_s())
                    sgMatchHaloRule(sgRule,grant,ruleList,True)
                return False
    print "Matching SG: %s" % sg.name
    return True


def addPredefinedRules(svcName,port,protocol,inbound,outbound):
    global predefinedRules
    chainList = []
    if (inbound):
        chainList.append("INPUT")
    if (outbound):
        chainList.append("OUTPUT")
    for chain in chainList:
        rule = { "action": "ACCEPT", "chain": chain, "connection_states": None }
        rule['firewall_service'] = { "name": svcName, "protocol": protocol, "port": port }
        predefinedRules.append(rule)


def isSecurityGroupInList(mygroup,sglist):
    if (mygroup == None) or (sglist == None):
        return False
    for sg in sglist:
        if (mygroup.name == sg.name):
            return True
    return False

addPredefinedRules('HTTPS', 443,'TCP',False,True) # outbound HTTPS
addPredefinedRules('DNS_TCP',53,'TCP',False,True)  # outbound DNS/TCP
addPredefinedRules('DNS',53,'UDP',False,True)  # outbound DNS/UDP
addPredefinedRules('SSH',22,'TCP',False,True)  # outbound SSH

processCommandLine(sys.argv[1:])
if (len(sys.argv) < 2) or (serverIP == None):
    usage()
    sys.exit(1)

fwp = None
apiCon = getHaloConnection(authFilename,os.path.dirname(sys.argv[0]))
if (apiCon == None):
    print >>sys.stderr, "Unable to connect to Cloudpassage"
    sys.exit(2)
group = findGroupContainingServerByIP(apiCon, serverIP, serverGroupName)
if (group == None):
    print >>sys.stderr,"Not able to find server with IP %s in any Halo Server Group" % serverIP
    sys.exit(2)
elif (group.linux_firewall_policy_id != None):
    fwp = cpfwpolicies.FirewallPolicies.byId(apiCon,group.linux_firewall_policy_id)

if (group != None):
    print "Found server in group: %s" % group.name
    if (verbose):
        print "Linux FWP ID: %s" % group.linux_firewall_policy_id
        print "Windows FWP ID: %s" % group.windows_firewall_policy_id
    if (fwp != None):
        dumpFirewallPolicy(fwp)
    else:
        print >> sys.stderr,"Server group does not have a Linux firewall policy"
        sys.exit(3)

print ""
ec2conn = None
regionStr = "default region"
if (awsRegionName != None):
    ec2conn = boto.ec2.connect_to_region(awsRegionName)
    regionStr = "region \"%s\"" % awsRegionName
else:
    ec2conn = boto.connect_ec2()
if (ec2conn == None):
    print >>sys.stderr, "Unable to connect to %s" % regionStr
    sys.exit(2)

(reservation, instance) = findInstanceByIP(ec2conn, serverIP)
if (reservation == None) or (instance == None):
    print >>sys.stderr, "Not able to find instance with IP %s in %s" % (serverIP, regionStr)
    sys.exit(3)
groups = aws_ec2.SecurityGroup.all(ec2conn)
if (verbose):
    print "reservation=%s instance=%s" % (reservation.id, instance.id)
    if (reservation.groups == None):
        print "  no security groups"
    else:
        for sg in reservation.groups:
            if (sg == None):
                "  missing security group"
            else:
                print "  reservation security group=%s" % sg.name
    if (instance.groups == None):
        print "  no security groups"
    else:
        for sg in instance.groups:
            if (sg == None):
                "  missing security group"
            else:
                print "  instance security group=%s" % sg.name
if (extraVerbose):
    for sg in groups:
        print "Security Group: %s" % sg.to_s()

addCount = 0
sgList = []
sgMap = {}
for sg in instance.groups:
    sgList.append(sg.name)
    sgMap[sg.name] = sg
fwpRuleList = fwp.rules + predefinedRules
for sg in groups:
    if (extraVerbose):
        print "Looking up SG:\n  %s" % sg.to_s()
    # sg = matchHaloRuleToSG(rule,groups,group.name)
    if not sgMatchesHaloFWP(sg,fwpRuleList,group.name):
        continue
    if not (sg.name in sgList):
        sgList.append(sg.name)
        sgMap[sg.name] = sg.boto_obj
    if isSecurityGroupInList(sg,instance.groups) or isSecurityGroupInList(sg,reservation.groups):
        print "SG already attached to instance"
    else:
        print "Need to attach SG to instance"
        addCount += 1
instance_sg_list = []
for name in sgList:
    instance_sg_list.append(sgMap[name].id)
if (addCount > 0) and (not dryRun):
    try:
        if instance.modify_attribute("groupSet",instance_sg_list):
            print "ModifyAttribute: success"
        else:
            print "ModifyAttribute: failed"
    except boto.exception.EC2ResponseError:
        print >>sys.stderr, "Failed to modify list of SGs attached to instance"
        print >>sys.stderr, "You may have too many SGs"
elif (dryRun):
    print "Dry run, no changes made"
else:
    print "No changes needed"
