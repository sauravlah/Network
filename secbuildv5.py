#!/usr/bin/python
# Name: sec_build.py
# Purpose: Takes a GIS Port matrix, and spits out a set of terraform files for SecLists
# Author: C.R.Chapman
majorVersion = 0
minorVersion = 5
patchVersion = 'd'

__author__ = "Christian Chapman"
__version__ = "{}.{}.{}".format(majorVersion, minorVersion, patchVersion)
# NOTES
# This version from version c removes the Seclist class, moves the functionality into Subnet. Subnet then uses a single dictionary for the rules, then chunks these up into the application seclists
# By keeping them in one list improves deduplication, it will also aid in our future summarisation effort

# TODO
# summarisation of ports and subnets
# Alter input to take new column for the transport layer protocol

tenancy = "sandbox"  # sandbox or prod
# from openpyxl import Workbook, load_workbook
import re
import argparse
import os
import logging
import sys

import const

# general constants
const.MAXRULE = 50
const.APPSECLIST = 3
const.GENSECLIST = 2

# extracted row indexes
const.SRCNAM = 0
const.SRCADD = 1
const.DSTNAM = 2
const.DSTADD = 3
const.MIN = 4
const.MAX = 5
const.PROTO = 6

# import file indexes
const.SOURCENAME = 7
const.SOURCEADD = 8
const.DESTNAME = 9
const.DESTADD = 10
const.MINPORT = 11
const.MAXPORT = 12
const.PROTOCOL = 14
const.COMMENT = 16

# network file fields
const.NETSUBNETNAME = 0
const.NETLONGNAME = 1
const.NETJIRA = 2
const.NETOCID = 3
const.NETCIDR = 4
const.NETSUFFIX = 5
const.NETEXTERNAL = 6
const.NETREGION = 7
const.NETCOMPARTMENT = 8
const.NETAD = 9
const.NETCOMPARTMENTOCID = 10
const.NETSTATUS = 11

# AD OCI region names to internal naming construction
ad_list = dict()
ad_list['us-ashburn-1'] = 'ash1'
ad_list['eu-frankfurt-1'] = 'fra1'
ad_list['us-phoenix-1'] = 'phx1'

# cidrname = 0
# cidradd = 1
# subnetname = 2
# region=3
# ad=4
# compartment=5
# seclistname=6
# displayname=7
const.NetTemplate = """variable "{0}"	{{ default = "{1}" }}

resource "oci_core_subnet" "{2}" {{
    availability_domain       = "{{var.oragit-{3}-ad{4} }}"
    cidr_block                = "{{var.{0} }}"
    compartment_id            = "{{var.{5} }}"
    dhcp_options_id           = "{{oci_core_dhcp_options.oragit-{3}-dhcp1.id}}"
    display_name              = "{7}"
    vcn_id                    = "{{oci_core_virtual_network.oragit-{3}-vcn1.id}}"
    route_table_id            = "{{oci_core_route_table.oragit-{3}-rt1.id}}"
    security_list_ids         = [
                "{{oci_core_security_list.oragit-{3}-sec-vcn1-prod-general1.id}}",
                "{{oci_core_security_list.oragit-{3}-sec-vcn1-prod-general2.id}}",
                "{{oci_core_security_list.{6}-1.id}}",
                "{{oci_core_security_list.{6}-2.id}}",
                "{{oci_core_security_list.{6}-3.id}}",
    ]
}}
"""

# name = 1
# displayName=2
# region=3
# const.SecListTemplate = """
# resource "oci_core_security_list" "{1}" {
#    compartment_id  = "${{var.sandbox_compartment_git_networks_ocid}}"
#    display_name    = "{2}"
#    vcn_id          = "${{oci_core_virtual_network.oragit-{3}-vcn1.id}}"
#
# """

const.SecListHeader = """
resource "oci_core_security_list" "{}" {{
    compartment_id  =   "${{var.sandbox_compartment_git_networks_ocid}}"
    display_name    =   "{}"
    vcn_id          =   "${{oci_core_virtual_network.oragit-{}-vcn1.id}}"
"""

# format(commentString,self.protocol,self.highPort,self.lowPort,stateless,Protocol,direction,self.sourceAdd)
const.SecListRuleTemplate = """
{0}
    {{
    {1}_options {{
        "max" = "{2}"
        "min" = "{3}"
        }}
    stateless = "{4}"
    protocol = "{5}"
    {6} = "{7}"
    }},
"""

const.SecListRuleTemplateAll = """
{0}
    {{
    stateless = "{4}"
    protocol = "{5}"
    {6} = "{7}"
    }},
"""

const.SecListRuleTemplateICMP = """
{}
    {{
    icmp_options {{
        "type" = "{}"
        "code" = "{}"
        }}
    stateless = "{}"
    protocol = "{}"
    {} = "{}"
    }},
"""


class SecListRule:  # compartment, direction, statetype, Hostname, IP, Port, secListReference
    def __init__(self, SourceAdd, LowPort, HighPort, Protocol, Direction, Comment='', Stateful=True):
        # self.direction = Direction don't need as controled by the list, we choose the address
        # (wrongly termed SourceAdd) on destination or source on ouotput
        self.sourceAdd = SourceAdd
        self.lowPort = LowPort  # type on icmp
        self.highPort = HighPort  # code on icmp
        self.protocol = Protocol
        self.stateful = Stateful
        self.comment = ''  # this comment will preceed the rule on output
        self.direction = Direction

    def __key(self):
        return (self.sourceAdd, self.lowPort, self.highPort, self.protocol, self.direction)

    def __str__(self):
        return self.outputRule()

    def __eq__(self, other):
        if other.__hash__() == self.__hash__():
            # if isinstance(other, SecListRule) and self.sourceAdd == other.sourceAdd and self.lowPort == other.lowPort
            #  and self.highPort == other.highPort and self.protocol == other.protocol
            #  and self.direction == other.direction:
            return True
        else:
            return False

    def __ne__(self, other):
        if not (isinstance(other, SecListRule) and self.sourceAdd == other.sourceAdd and self.lowPort == other.lowPort
                and self.highPort == other.highPort and self.protocol == other.protocol
                and self.direction == other.direction):
            return True
        else:
            return False

    def __hash__(self):
        return hash(self.__key())

    # this returns a string of the seclist rules in the terraform syntax as a scalar string
    def outputRule(self):
        # sets the layer 3 protocol
        if self.protocol == "tcp":
            Protocol = "${var.Protocol-TCP}"
        elif self.protocol == "udp":
            Protocol = "${var.Protocol-UDP}"
        elif self.protocol == "icmp":
            Protocol = "${var.Protocol-ICMP}"
        elif self.protocol == "all":
            Protocol = "all"
        # do we need a better reference here to be able trackdown?
        else:
            raise ValueError("Invalid protocol: {0} for rule with comment {1}".format(self.protocol, self.comment))

        # sets stateful nature, by default we use stateful
        if self.stateful:
            stateless = str("false")
        else:
            stateless = str("true")

        # sets source or destination depending on whether this is an egress or an ingress rule
        if self.direction:
            direction = "destination"
        else:
            direction = "source"

        # write the string, with comment if set
        if self.comment != '':
            commentString = "###\n###\t" + self.comment + "\n###\n"
        else:
            commentString = ''
        # here we split the replies into three. ICMP with ports. Other protocols with ports.
        # And finally all protocols with all ports.
        # we may still need to add a single protocol with all ports
        # ICMP with ports
        if self.protocol == 'icmp' and self.lowPort != 'all':
            returnstring = \
                const.SecListRuleTemplateICMP.format(self.comment, self.lowPort, self.highPort, self.stateful,
                                                     direction,
                                                     self.sourceAdd)
        # otherwise tcp/udp with ports
        elif Protocol != "all" and self.protocol != 'icmp':
            returnstring = "{0}\t{{\n\t{1}_options\t{{\n\t\t\"max\"\t= \"{2}\"\n\t\t\"min\"\t= \"{3}\"\n\t\t}}\n\t\tstateless = \"{4}\"\n\t\tprotocol = \"{5}\"\n\t\t{6} = \"{7}\"\n\t}},\n".format(
                commentString, self.protocol, self.highPort, self.lowPort, stateless, Protocol, direction,
                self.sourceAdd)
        # or for all ports/protocols
        else:
            returnstring = commentString + "\t{\n\tstateless = \"" + stateless + "\"\n\tprotocol = \"" + Protocol + "\"\n\t" + direction + " = \"" + self.sourceAdd + "\"\n\t},\n"

        return returnstring

    def printRule(self):
        print (self.__str__)

    # returns 1 for egress, and 0 for ingress
    def getDirection(self):
        return self.direction

    def isEgressRule(self):
        if self.direction:
            return True
        else:
            return False

    def isIngressRule(self):
        if self.direction:
            return False
        else:
            return True

    def isSamePort(self, other):
        if isinstance(other, SecListRule) and self.highPort == other.highPort and self.protocol == other.protocol:
            return True
        else:
            return False

    def isSameAddress(self, other):
        if isinstance(other, SecListRule) and self.sourceAdd == other.sourceAdd:
            return True
        else:
            return False


class SecList:
    # TODO This is missing the compartment name, which we will need for the header output, but at the moment they are
    # all in the networks compartment
    def __init__(self, Name, DisplayName, Region, SubLists):
        self.name = Name
        self.displayName = DisplayName
        self.region = Region
        self.ingressRules = dict()
        self.egressRules = dict()
        self.numOfSublists = int(SubLists)
        # ingress = 0, egress = 1

    def __contains__(self, rule):
        # Should only ever contain SecListRules
        if isinstance(rule, SecListRule):
            # rule could either be in ingress or egress rule
            if rule in self.ingressRules or rule in self.egressRules:
                return True
        return False

    def __eq__(self, other):
        if self.name == other.name and self.region == other.region:
            return True
        else:
            return False

    def __hash__(self):
        return hash(self.__key())

    def __key(self):
        return (self.name, self.displayName, self.region)

    def __ne__(self, other):
        if self.name != other.name or self.region != other.region:
            return True
        else:
            return False

    def __str__(self):
        return self.name

    # following two defs allow us to check we haven't exceeded the 50 limit
    def numOfIngress(self):
        return len(self.ingressRules)

    def numOfEgress(self):
        return len(self.egressRules)

    # TODO replace ingress and egress adds with single unified rule, that takes a single seclistrule
    def addRule(self, seclistrule):
        if seclistrule.isIngressRule():
            # we hold all the rules inside this one list and divide up at the end so it's max rules (const.MAXRULE)
            #  times number of lists (const.APPSECLIST)
            if self.numOfIngress() < const.MAXRULE * self.numOfSublists:
                self.ingressRules[hash(seclistrule)] = seclistrule
                logging.debug(seclistrule)
            else:
                logging.debug(seclistrule.outputRule())
                raise ValueError("Too many rules trying to be added to {} Ingress, currently i{}:e{} rules"
                                 .format(self.name, len(self.ingressRules), len(self.egressRules)))
        elif seclistrule.isEgressRule():
            if self.numOfEgress() < const.MAXRULE * self.numOfSublists:
                self.egressRules[hash(seclistrule)] = seclistrule
                logging.debug(seclistrule)
            else:
                raise ValueError("Too many rules trying to be added to {0} Egress".format(self.name))
        else:
            raise ValueError("SecList Rule {0} has an invalid direction".format(self.name))

    # This rule takes a rule and remove from this rule set, if it is not
    def deleteRule(self, seclistrule):
        if seclistrule.isIngressRule():
            if seclistrule in self.ingressRules:
                del self.ingressRules[hash(seclistrule)]
                return 1
            else:
                return 0
        else:
            if seclistrule in self.egressRules:
                del self.egressRules[hash(seclistrule)]
                return 1
            else:
                return 0

    # creates new rule and adds to ingress lists
    def addIngressRule(self, Address, lowPort, upperPort, Protocol, Stateful=True):
        tempseclistrule = SecListRule(Address, lowPort, upperPort, Protocol, False, '', True)
        if tempseclistrule in self.ingressRules:
            logging.info("Duplicate rule found in {}".format(self.name))
            logging.debug("Seclist {}, seclist rule {}".format(self.name, tempseclistrule))
            return 0
        if self.numOfIngress() < const.MAXRULE * self.numOfSublists:
            self.ingressRules[hash(tempseclistrule)] = tempseclistrule
            logging.debug("Seclist {}, seclist rule {}".format(self.name, tempseclistrule))
        else:
            raise ValueError("Too many rules trying to be added to {0} Ingress".format(self.name))

    # creates new rule and adds to egress lists
    def addEgressRule(self, Address, lowPort, upperPort, Protocol, Stateful=True):
        tempseclistrule = SecListRule(Address, lowPort, upperPort, Protocol, True, '', True)
        if tempseclistrule in self.egressRules:
            logging.info("Duplicate rule found in {}".format(self.name))
            logging.debug("Seclist {}, seclist rule {}".format(self.name, tempseclistrule))
            return 0
        if self.numOfEgress() < const.MAXRULE * self.numOfSublists:
            self.egressRules[hash(tempseclistrule)] = tempseclistrule
            # logging.debug("Seclist {}, seclist rule {}".format(self.name, tempseclistrule))
        else:
            raise ValueError("Too many rules trying to be added to {0} Egress".format(self.name))

    def _getKeys(self, egress):
        if egress:
            for key, value in self.egressRules:
                return key
        else:
            for key, value in self.ingressRules:
                return key

    def getName(self):
        return self.name

    # output both SecLists (ingress and egress) for all the SecLists we use
    def outputSecList(self):  # returns a list, one line per slot
        '''This function returns the terraform file output strings for the associated seclists.
        This function will create three strings and return them in a tuple'''

        # We create two lots of rules, ingress and egress. These then get passed into the seclist strings
        ingressstring = list()
        egressstring = list()
        returnStrings = list()
        index = 0
        alist = str()

        for index, key in enumerate(self.ingressRules):
            if type(self.ingressRules[key]) is SecListRule:
                logging.debug("Writing ingress rule {}, to rule {:d}".format(index + 1, (index // const.MAXRULE) + 1))
                alist += self.ingressRules[key].outputRule()
                if (index + 1) % const.MAXRULE == 0:
                    ingressstring.append(alist)
                    alist = ""
                    logging.info("Written ingress {} on {} seclist".format(index, self.name))
            else:
                logging.critical("failed with key {} in ingressRules".format(key))
        # logging.info("Filled ingress on {} with {} seclist".format(self.name,index))

        alist = ""

        for index, key in enumerate(self.egressRules):
            if type(self.egressRules[key]) is SecListRule:
                logging.debug("Writing egress rule {}, to rule {:d}".format(index + 1, (index // const.MAXRULE) + 1))
                alist += self.egressRules[key].outputRule()
                if (index + 1) % const.MAXRULE == 0:
                    egressstring.append(alist)
                    alist = ""
                    logging.info("Written egress {} on {} seclist".format(index, self.name))
            else:
                logging.critical("failed with key {} in ingressRules".format(key))
        # logging.info("Filled egress on {} with {} seclist".format(self.name,index))

        for i in range(0, self.numOfSublists):
            alist = str()
            # add header section
            # TODO we still have it here showing sandbox rather than prod for the full implmentation. Do we need the ability to alter this or in future set to prod?
            alist = const.SecListHeader.format("{}-{}".format(self.name, i + 1), "{}-{}".format(self.name, i + 1),
                                               self.region)
            # add ingress header
            alist = alist + "ingress_security_rules = [\n"
            # we want to take off the next const.MAXRULE
            try:
                # ingress
                alist += ingressstring[i]
            except IndexError:
                # if we get and index error that is fine, there is no data for this seclist
                logging.info("Created ingress values in map {} on {} seclist".format(i, self.name))
            # add ingress footer
            alist = alist + "\t]\n"
            # add egress header
            alist = alist + "egress_security_rules = [\n"
            try:
                # egress
                alist += egressstring[i]
            except IndexError:
                logging.info("Created egress values in map {} on {} seclist".format(i, self.name))
            # add egress footer
            alist = alist + "\t]\n"
            # add footer section
            alist = alist + "}"
            returnStrings.append(alist)
        return returnStrings

    def printSecList(self):
        print (self.__str__())
    # End of SecList


class Subnet:
    '''This element reproduces a single subnet within the OCI terraform code. Subnets in the same Application area, but different ADs will be represented differently
    A single seclist is contained within the subnet (pointed to in an external dictionary, self.secListDict).
    Rules are added to the Subnet, which then passes it on to the Seclist, this will create duplicates if there are two Subnets in the samme application area as they try to write to the same SecList, but the SecList will
    '''

    def __init__(self, Name, DisplayName, Region, CIDR, Compartment, AD, VCN, dhcpOptions, seclists):
        self.name = Name
        self.displayName = DisplayName
        self.region = Region
        self.cidr = CIDR
        self.ad = AD
        self.vcn = VCN
        self.dhcpOptions = dhcpOptions
        self.compartment = Compartment

        # delete this lines once we successfully can use the new form in this class
        # create the three seclist names, hash these names and add them to our ref list
        # self.seclists = [ hash(self.__convertToSec(Name)+'-1'), hash(self.__convertToSec(Name)+'-2'), hash(self.__convertToSec(Name)+'-3')]
        # seclists[hash(self.__convertToSec(Name)+'-1')] = SecList(self.__convertToSec(Name)+'-1',self.__convertToSec(Name)+'-1',Region)
        # seclists[hash(self.__convertToSec(Name)+'-2')] = SecList(self.__convertToSec(Name)+'-2',self.__convertToSec(Name)+'-2',Region)
        # seclists[hash(self.__convertToSec(Name)+'-3')] = SecList(self.__convertToSec(Name)+'-3',self.__convertToSec(Name)+'-3',Region)

        self.secListNameHash = hash(self.__convertToSec(Name))
        seclist = SecList(self.__convertToSec(Name), self.__convertToSec(Name), Region, const.APPSECLIST)
        self.secListDict = seclists
        self.secListDict[self.secListNameHash] = seclist
        # new model might have a single dictionary directly attached into this subnet, all the rules get dropped into it
        # we then need to summarise (do we automatically do this, or do we trigger this)
        # we need to alert on 75% full notification and >100% full
        # when we print this out we shufflle 50 into a pile, create the seclist
        # that X three

    def __contains__(other):
        if self.name == other.name and self.region == other.region:
            return True
        else:
            return False

    def __eq__(self, other):
        logging.debug("Matching {} against {}".format(other.name, self.name))
        if isinstance(other, Subnet):
            logging.debug("Matching on type")
            return self.name == other.name and self.region == other.region
        elif isinstance(other, str):
            logging.debug("matching on string {}:{}".format(self.name, other.name))
            return self.name == other.strip()
        else:
            logging.debug("Failed to match {}".format(self.name()))
            return False

    def __hash__(self):
        # altering the hash based on the cidr address rather than name
        logging.debug("Subnet hash invoked {}".format(self.cidr))
        return hash(self.cidr)

    def __ne__(self, other):
        logging.debug("Matching against {}".format(self.name))
        if isinstance(other, Subnet):
            logging.debug("Matching on type")
            return self.name != other.name and self.region != other.region
        elif isinstance(other, str):
            logging.debug("matching on string {}:{}".format(self.name, other))
            return self.name != other.strip()
        else:
            return False

    # this needs to be sorted out for the future
    # def __repr__(self):
    #    return '%s(%r)' % (self.__class__.__name__,self.name,self.displayName,self.region,self.environment,self.compartment,self.subnetName,self.seclists)

    def __str__(self):
        return str(self.displayName)

    # net to cidr address
    def __convertToCIDR(self, string):
        match = re.match('^(oragit-)(ash|phx)(\d-)net-(vcn1-ad[1-3]-.*)$', string)
        if match:
            return match.group(1) + match.group(2) + match.group(3) + "cidr-" + match.group(4)
        else:
            match = re.match('^(.*)-ad[1-3](.*)', string.strip())
            if match:
                return match.group(1) + match.group(2) + '-cidr'
            return string.strip() + "-cidr"

    # net to sec value
    def __convertToSec(self, string):
        match = re.match('^(oragit-)(ash|phx)(\d-)net-(vcn\d-)ad[1-3]-(.*)$', string.strip())
        if match:
            return match.group(1) + match.group(2) + match.group(3) + "sec-" + match.group(4) + match.group(5)
        else:
            match = re.match('^(.*)-ad[1-3](.*)', string.strip())
            if match:
                return match.group(1) + match.group(2) + '-sec'
            return string.strip() + "-sec"

    def __parse(self, subnetaddress):
        # this will ensure and address is on a common format, returning False if not valid at all
        # expected entrey \d+\.\d+\.\d+\.\d+(\/\d{1,2})? further checks on values and the subnet address is between 0 and 32 inclusive
        pass

    def activeSecList(self, direction, seclists):
        if direction:
            if seclists.getSeclist(self.seclist[0]).numOfEgress() < const.MAXRULE:
                return self.seclist(i)
            elif seclists.getSeclist(self.seclist[1]).numOfEgress() < const.MAXRULE:
                return self.seclist(i)
            elif seclists.getSeclist(self.seclist[2]).numOfEgress() < const.MAXRULE:
                return self.seclist(i)
            else:
                raise SystemExit("Too many Egress rules on {0}".format(self.name))

        else:
            if seclists.getSeclist(self.seclist[0]).numOfIngress() < const.MAXRULE:
                return self.seclist(i)
            elif seclists.getSeclist(self.seclist[1]).numOfIngress() < const.MAXRULE:
                return self.seclist(i)
            elif seclists.getSeclist(self.seclist[2]).numOfIngress() < const.MAXRULE:
                return self.seclist(i)
            else:
                raise SystemExit("Too many Ingress rules on {0}".format(self.name))

    def addSecListLine(self, Direction, Address, lowPort, upperPort, Protocol, Stateful=True):
        '''Adding a new seclist rule into the subnet. This is passed to the seclist, which deduplicates
        The rules is decided which direction to go from the calling module outside (0 ingress, 1 egress)
        These seclists are only ever in a subnet, the general seclists are never covered by this module
        '''

        if Direction:
            if self.secListDict[self.secListNameHash].numOfEgress() < const.MAXRULE * const.APPSECLIST:
                self.secListDict[self.secListNameHash].addEgressRule(Address, lowPort, upperPort, Protocol, Stateful)
            ##            if self.secListDict[self.seclists[0]].numOfEgress() < const.MAXRULE:
            ##                self.secListDict[self.seclists[0]].addEgressRule(Address, lowPort, upperPort, Protocol, Stateful)
            ##                logging.debug("Adding rule {} to {}".format(self.secListDict[self.seclists[0]].numOfEgress(), self.secListDict[self.seclists[0]]))
            ##            elif self.secListDict[self.seclists[1]].numOfEgress() < const.MAXRULE:
            ##                self.secListDict[self.seclists[1]].addEgressRule(Address, lowPort, upperPort, Protocol, Stateful)
            ##                logging.debug("Adding rule {} to {}".format(self.secListDict[self.seclists[1]].numOfEgress(),self.secListDict[self.seclists[2]]))
            ##            elif self.secListDict[self.seclists[2]].numOfEgress() < const.MAXRULE:
            ##                self.secListDict[self.seclists[2]].addEgressRule(Address, lowPort, upperPort, Protocol, Stateful)
            ##                logging.debug("Adding rule {} to {}".format(self.secListDict[self.seclists[2]].numOfEgress(),self.secListDict[self.seclists[2]]))
            else:
                logging.critical("Too many Egress rules on {0}".format(self.name))
                # raise SystemExit("Too many Egress rules on {0}".format(self.name))

        else:
            if self.secListDict[self.secListNameHash].numOfIngress() < const.MAXRULE * const.APPSECLIST:
                self.secListDict[self.secListNameHash].addIngressRule(Address, lowPort, upperPort, Protocol, Stateful)
            ##            if self.secListDict[self.seclists[0]].numOfIngress() < const.MAXRULE:
            ##                self.secListDict[self.seclists[0]].addIngressRule(Address, lowPort, upperPort, Protocol, Stateful)
            ##                logging.debug("Adding rule {} to {}".format(self.secListDict[self.seclists[0]].numOfIngress(),self.secListDict[self.seclists[0]]))
            ##            elif self.secListDict[self.seclists[1]].numOfIngress() < const.MAXRULE:
            ##                self.secListDict[self.seclists[1]].addIngressRule(Address, lowPort, upperPort, Protocol, Stateful)
            ##                logging.debug("Adding rule {} to {}".format(self.secListDict[self.seclists[0]].numOfIngress(),self.secListDict[self.seclists[2]]))
            ##            elif self.secListDict[self.seclists[2]].numOfIngress() < const.MAXRULE:
            ##                self.secListDict[self.seclists[2]].addIngressRule(Address, lowPort, upperPort, Protocol,  Stateful)
            ##                logging.debug("Adding rule {} to {}".format(self.secListDict[self.seclists[0]].numOfIngress(),self.secListDict[self.seclists[1]]))
            else:
                logging.critical("Too many Ingress rules on {0}".format(self.name))
                # raise SystemExit("Too many Ingress rules on {0}".format(self.name))

    def getCidr(self):
        return self.cidr

    def getName(self):
        return self.name

    # This returns the hash of the seclist
    def getSecList(self, i):
        return self.seclists[i]

    def matchThisSubnet(self, subnetrange):
        # TODO check format of the passed range
        if subnetrange == self.cidr:
            return True
        return False

    # def returnSecLists(self):
    #    secList = list()
    #    self.seclists[0].outputSecList()
    #    print "From Subnet"
    #    return secList

    # prints out number of rules totally used by the applications
    def rulesUsed(self):
        '''This returns the number of seclist rules applied to this network in the tuple (ingress, egress)'''
        egress = self.secListDict[self.secListNameHash].numOfEgress()
        ingress = self.secListDict[self.secListNameHash].numOfIngress()
        return (ingress, egress)

    # cidrname = 0
    # cidradd = 1
    # subnetname = 2
    # region=3
    # ad=4
    # compartment=5
    # seclistname=6
    # displayname=7
    # outputs the terraform file declaration
    def outputSubnetFile(self):
        return const.NetTemplate.format(self.__convertToCIDR(self.name), self.cidr, self.name, self.region, self.ad,
                                        self.compartment, self.__convertToSec(self.name), self.displayName)

    # outputs all seclitst
    def outputSecLists(self):
        '''This returns three strings in a tuple, one for each of the three application seclists'''
        ##        returnString = str()
        ##        for internalList in range (1,4):
        ##            print ("SecList "+str(internalList))
        ##            returnString += self.secListDict[hash(self.__convertToSec(self.name)+'-'+str(internalList))].outputSecList()+"\n"
        return self.secListDict[self.secListNameHash].outputSecList()

    ##        #so we need to return 3 lists (the SecLists) full of 50 rules
    ##        returnList = list()
    ##        #so we start with the first one and fill it, and go to the next
    ##
    ##        secListRuleNumber = 0
    ##        #so the is idea is to keep a count as we go through and populate lists with the three strings
    ##        for irule in self.ingressSecListRules:
    ##            returnString = irule.outputRule()
    ##            secListRuleNumber += 1
    ##            if secListRuleNumber == const.MAXRULES:
    ##                #So we've hit the end of this list need to finish up, by adding it into position
    ##                returnList.append(returnString)
    ##                #restart counting rules for this SecList
    ##                secListRuleNumber = 0
    ##                #then reset the text
    ##                returnString = ""
    ##

    # output a single seclist (egress and ingress, takes a decimal)
    def outputSecList(self, seclist):
        '''This method takes a single value from 1 to 3 inclusive and returns the appropriate seclist output.'''
        if seclist < 1 or seclist > 3:
            raise ValueError("Seclist index value must be from 1 to 3")
        ##        returnString = str()
        ##        return self.secListDict[hash(self.__convertToSec(self.name)+'-'+str(seclist))].outputSecList()
        return self.secListDict[self.secListNameHash].outputSecList()[seclist - 1]


# END OF Subnet

class SubnetFile:
    '''This class is the connection to a network csv file with lists of all the networks to be built.
    networks are removed by not being included in these files'''

    def __init__(self, filename, startrow):
        try:
            # if we've defined this then we must have some data else forget it
            if filename is not None:
                ##                self.ws2 = load_workbook(filename) #throw an error is unable to open the file
                self.ws = open(filename, 'r')
        except IOError as e:
            print ("Unable to open the Subnet file {0}: {1}".format(filename, e))
            exit(0)
        # may not need the following line, it was used in the past to catch corrupted files
        except Exception as e:
            print ("File corrupted {0}".format(e))
            exit(0)

    ##        else:
    ##            self.SNSheet = self.ws2[subnetsheet]

    def __ipFormatCheck(self, ip_str):
        pattern = r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        if re.match(pattern, ip_str):
            return True
        else:
            return False

    # takes a dictionary and adds subnets to it
    def addToList(self, subnets, seclists):
        for index, row in enumerate(self.getSubnets()):
            # finally we add a special case for the general seclists (10.15.0.0/16 /17 or /18)
            tempsubnet = Subnet(row[0], row[1], row[5], row[2], row[4], row[3], row[6], row[7], seclists)
            # hash index now using cidr
            subnets[hash(row[2])] = tempsubnet
            logging.debug(
                "Adding {} with cidr {} and hash {} from line {}".format(row[0], row[2], hash(row[2]), index + 1))

    def getSubnets(self):
        '''The function returns a list of lists of all the rows in the subnet file
        The list of the fields is set out in the const.NET* variables at the top of the file
        '''
        alist = list()
        for index, line in enumerate(self.ws):
            row = line.split(',').strip()
            '''we do a check just to make sure none of the values are blank, otherwise fail this line'''
            if not (row[const.NETSUBNETNAME] == None or row[const.NETLONGNAME] == None or row[const.NETREGION] == None
                    or row[const.NETCIDR] == None or row[4] == None or row[5] == None or row[6] == None or row[
                        7] == None):
                subnet = row[const.NETCIDR].strip()
                if not self.__ipFormatCheck(subnet):
                    logging.error("Invalid IP address on line " + str(index + 1) + " " + line)
                    raise ValueError("Invalid IP address on line " + str(index + 1) + " " + line)
                # TODO add the function to put out the correct region from the input
                region = 'ash1'
                # TODO add the function to create select the correct AD
                # Here we look to check that the AD field is as we expect and which AD it is. If this matches we set it
                # and then assign it for use to create the subnet object, otherwise we skip this row
                match_str = re.compile('a([1-3])-v\d-\w{3}\d-oragit', re.I)
                matching = match_str.search(row[const.NETAD])
                if matching:
                    ad = match_str.group(1)
                else:
                    logging.error("Incorrectly formatted AD field {} in row {}".format())
                    continue
                # TODO add the dhcpOptions for each region
                dhcpOptions = "oragit-ash1-dhcp1"
                alist.append((row[const.NETSUBNETNAME], row[const.NETSUBNETNAME], row[const.NETREGION],
                              row[const.NETCOMPARTMENT], row[const.NETCOMPARTMENT], row[ad], "1", dhcpOptions))
        # iterate through all the rows
        ##        for index, row in enumerate(self.SNSheet.iter_rows()):
        ##            #format is name, ad number, vcn, region, compartment, tenancy,
        ##            #def __init__(self, Name, DisplayName,Region,CIDR,Compartment,VCN)
        ##            if not( row[const.NETSUBNETNAME].internal_value == None or row[const.NETSUBNETNAME].internal_value == None or row[const.NETREGION].internal_value == None
        ##                    or row[const.NETCIDR].internal_value == None or row[4].internal_value == None or row[5].internal_value == None or row[6].internal_value == None or row[7].internal_value == None):
        ##                subnet = row[2].internal_value.strip()
        ##                if not self.__ipFormatCheck(subnet):
        ##                    logging.error("Invalid IP address on line "+str(index+1)+" "+line)
        ##                    raise ValueError("Invalid IP address on line "+str(index+1)+" "+line)
        ##                alist.append((row[0].internal_value, row[1].internal_value, row[2].internal_value, row[3].internal_value, row[4].internal_value, row[5].internal_value, row[6].internal_value, row[7].internal_value))
        ##            elif index > self.startRow: # and not (row[0].internal_value == None or row[1].internal_value == None or row[2].internal_value == None or row[3].internal_value == None or row[4].internal_value == None or row[5].internal_value == None or row[6].internal_value == None or row[7].internal_value == None):
        ##                logging.error("Invalid data on row "+str(index+1))
        ##                raise ValueError("Invalid data on row "+str(index+1))
        return alist


# END OF SubnetFile

# This class was originally built just to take in the Port Matrix elements
# It can now take in a subnet spreadsheet, that could be separate or in the same files
class PortMatrix:
    def __init__(self, filename, startrow):
        self.fileName = filename
        self.startRow = startrow
        try:
            self.ws = open(self.fileName, 'r')  # throw an error is unable to open the file
        except IOError as e:
            print ("Unable to open the Port Matrix file {0}: {1}".format(filename, e))
            exit(0)
        #        except BadZipfile as e:
        #            print "File corrupted {0}".format(e)
        #            exit(0)
        except Exception as e:
            print (e)
            exit(0)
        else:
            self.currentRow = 0
            self.startRow = startrow
            # self.PMSheet = self.ws[pmsheet]
            # TODO perhaps keep a cached version of the spreadsheet worksheet
            # self.wsseclist = getAllRows()

    # net to cidr address
    def __convertTocidr(self, string):
        match = re.match('^(oragit-)(ash|phx)(\d-)net-(vcn1-ad[1-3]-.*)$', string)
        return match.group(1) + match.group(2) + match.group(3) + "cidr-" + match.group(4)

    # set of utility functions for crafting elements
    def __isPortRange(self, stringIN):
        stringF = str(stringIN).strip()
        # is the cell containing either 1 number or two number separated by a dash or Any:Any
        if re.search('^\d{1,5}(-\d{1,5})?$', stringF) or re.search('^all$', stringF):
            return True
        raise ValueError("Invalid Port {0}".format(stringIN))
        return False

    def __generalSecList(self, Direction, sname, sipaddress, dname, dipaddress, Protocol, minport, maxport, seclist):
        try:
            lowPort, upperPort = self.__returnPorts(minport, maxport)
        except ValueError as e:
            logging.error("Found invalid port range {}, skipping row".format(port))

        if Direction:
            # phoenix egress
            address = self.__nameOrAddress(dname, dipaddress)
            if sipaddress == '10.15.0.0/16' or sipaddress == '10.15.0.0/17' or sipaddress == '10.15.0.0/18':
                if seclist[hash('oragit-sec-phx1-vnc1-prod-general-1')].numOfEgress() < const.MAXRULE:
                    logging.debug("Adding rule {} to {}".format(
                        seclist[hash('oragit-sec-phx1-vnc1-prod-general-1')].numOfEgress(),
                        'oragit-sec-phx1-vnc1-prod-general-1'))
                    seclist[hash('oragit-sec-phx1-vnc1-prod-general-1')].addEgressRule(address, lowPort, upperPort,
                                                                                       Protocol, True)
                elif seclist[hash('oragit-sec-phx1-vnc1-prod-general-2')].numOfEgress() < const.MAXRULE:
                    logging.debug("Adding rule {} to {}".format(
                        seclist[hash('oragit-sec-phx1-vnc1-prod-general-2')].numOfEgress(),
                        'oragit-sec-phx1-vnc1-prod-general-2'))
                    seclist[hash('oragit-sec-phx1-vnc1-prod-general-2')].addEgressRule(address, lowPort, upperPort,
                                                                                       Protocol, True)
                else:
                    # print "Too many Egress rules on {0}".format(self.name)
                    logging.critical("Too many Egress rules on {0}".format(self.name))
            # ashburn egress
            if sipaddress == '10.15.0.0/16' or sipaddress == '10.15.0.0/17' or sipaddress == '10.15.64.0/18':
                if seclist[hash('oragit-sec-ash1-vcn1-prod-general-1')].numOfEgress() < const.MAXRULE:
                    logging.debug("Adding rule {} to {}".format(
                        seclist[hash('oragit-sec-ash1-vcn1-prod-general-1')].numOfEgress(),
                        'oragit-sec-ash1-vcn1-prod-general-1'))
                    seclist[hash('oragit-sec-ash1-vcn1-prod-general-1')].addEgressRule(address, lowPort, upperPort,
                                                                                       Protocol, True)
                elif seclist[hash('oragit-sec-ash1-vcn1-prod-general-2')].numOfEgress() < const.MAXRULE:
                    logging.debug("Adding rule {} to {}".format(
                        seclist[hash('oragit-sec-ash1-vcn1-prod-general-2')].numOfEgress(),
                        'oragit-sec-ash1-vcn1-prod-general-2'))
                    seclist[hash('oragit-sec-ash1-vcn1-prod-general-2')].addEgressRule(address, lowPort, upperPort,
                                                                                       Protocol, True)
                else:
                    # print "Too many Egress rules on {0}".format(self.name)
                    logging.critical("Too many Egress rules on {0}".format(self.name))

        else:
            # phoenix ingress
            address = self.__nameOrAddress(sname, sipaddress)
            if dipaddress == '10.15.0.0/16' or dipaddress == '10.15.0.0/17' or dipaddress == '10.15.0.0/18':
                if seclist[hash('oragit-sec-phx1-vnc1-prod-general-1')].numOfIngress() < const.MAXRULE:
                    logging.debug("Adding rule {} to {}".format(
                        seclist[hash('oragit-sec-phx1-vnc1-prod-general-1')].numOfIngress(),
                        'oragit-sec-phx1-vnc1-prod-general-1'))
                    seclist[hash('oragit-sec-phx1-vnc1-prod-general-1')].addIngressRule(address, lowPort, upperPort,
                                                                                        Protocol, True)
                elif seclist[hash('oragit-sec-phx1-vnc1-prod-general-2')].numOfIngress() < const.MAXRULE:
                    logging.debug("Adding rule {} to {}".format(
                        seclist[hash('oragit-sec-phx1-vnc1-prod-general-2')].numOfIngress(),
                        'oragit-sec-phx1-vnc1-prod-general-2'))
                    seclist[hash('oragit-sec-phx1-vnc1-prod-general-2')].addIngressRule(address, lowPort, upperPort,
                                                                                        Protocol, True)
                else:
                    # print "Too many Ingress rules on Phoenix General"
                    logging.critical("Too many Ingress rules on {0}".format(self.name))
            # ashburn ingress
            if dipaddress == '10.15.0.0/16' or dipaddress == '10.15.0.0/17' or dipaddress == '10.15.64.0/18':
                if seclist[hash('oragit-sec-ash1-vcn1-prod-general-1')].numOfIngress() < const.MAXRULE:
                    logging.debug("Adding rule {} to {}".format(
                        seclist[hash('oragit-sec-ash1-vcn1-prod-general-1')].numOfIngress(),
                        'oragit-sec-ash1-vcn1-prod-general-1'))
                    seclist[hash('oragit-sec-ash1-vcn1-prod-general-1')].addIngressRule(address, lowPort, upperPort,
                                                                                        Protocol, True)
                elif seclist[hash('oragit-sec-ash1-vcn1-prod-general-2')].numOfIngress() < const.MAXRULE:
                    logging.debug("Adding rule {} to {}".format(
                        seclist[hash('oragit-sec-ash1-vcn1-prod-general-2')].numOfIngress(),
                        'oragit-sec-ash1-vcn1-prod-general-2'))
                    seclist[hash('oragit-sec-ash1-vcn1-prod-general-2')].addIngressRule(address, lowPort, upperPort,
                                                                                        Protocol, True)
                else:
                    # print "Too many Ingress rules on Ashburn General"
                    logging.critical("Too many Ingress rules on {0}".format(self.name))

    def __isGeneralSecList(self, line):
        generallists = ('10.15.0.0/16', '10.15.0.0/17', '10.15.0.0/18', '10.15.64.0/18')
        address = line
        for a in generallists:
            if a == address:
                return True
        return False

    # This will figure out which of and address or ip address to use. If the subnet name starts with oragit it presumes use the name
    # It also chose which which pair to look at depending on the line value, which needs to be calculated by the calling code
    # If the line exceeds the number of lines in the corresponding choice, it defaults to the first one
    # finally if a it is an IP address it makes sure there is a valid CIDR suffix attached, otherwise sets it to /32
    def __nameOrAddress(self, cell1, cell2):
        # if we have name or address which do we use?
        # if re.search("^oragit",cell1):
        # new version looks up the names as the hash (should fail everytime)
        if hash(cell1) in subnets and subnets[hash(cell1)].getCidr() == cell2:
            logging.debug("Returned {} which has ip {}".format(cell1, cell2))
            return "${var." + self.__convertTocidr(cell1) + "}"
        else:
            addressreturn = cell2.strip()
            # see if it ends in /XX
            m = re.search('^([\d.]+)\/(\d\d?)$', addressreturn)
            if m:
                logging.debug("Looking at address {} with subnet length {}".format(m.group(1), m.group(2)))
                # if yes is the value between 0 and 32 inclusive
                if m.group(2) > -1 or m.group(2) < 33:
                    logging.debug("Returning IP {} from subnet {}".format(cell2, cell1))
                    return addressreturn
            # else make it /32 as a safety precaution
            m = re.search('^([\d.]+)', addressreturn)
            if m:
                logging.warning("Returning IP {} which has no mask, setting to /32 from subnet {}".format(cell2, cell1))
                return m.group(1) + '/32'
            else:
                logging.debug("Could not determine the IP, cell1 = {}; cell2 = {}".format(cell1, cell2))
                return None

    # figure out whether a range, a single port, or all ports
    def __returnPorts(self, portString, portString2):
        # so no parsing of the actual values here
        portString = str(portString).strip()
        logging.debug("Request for ports given portString {}, portString2 {}".format(portString, portString2))
        if portString == 'all' or portString2 == 'all' or (int(portString) == 1 and int(portString2) == 65535):
            logging.debug(
                "Detecting an all statement using portString {}, portString2 {}".format(portString, portString2))
            return ('all', 'all')
        elif re.search("^\d{1,5}$", portString) and re.search("^\d{1,5}$", portString2):
            return (portString, portString2)
        else:
            raise ValueError("Invalid port value {}-{}".format(portString, portString2))

    def __returnProtocol(self, protString):
        if re.search('all', protString, re.I):
            return 'all'
        elif re.search('udp/?\w*', protString, re.I):
            return 'udp'
        elif re.search('tcp/?\w*', protString, re.I):
            return 'tcp'
        elif re.search('icmp/?\w*', protString, re.I):
            return 'icmp'
        else:
            raise ValueError("Invalid protocol value {}".format(protString))

    # takes a dictionary for subnets and adds rules to
    # TODO reduce the
    def addToConfig(self, subnets, seclists):
        if not isinstance(subnets, dict):
            raise ValueError("{0} is not a valid".format(subnets))
        if not isinstance(seclists, dict):
            raise ValueError("{0} is not a valid".format(seclists))

        # not sure why these two lines are here
        #        seclists[hash('oragit-sec-phx1-vnc1-prod-general-1')].addIngressRule('all', lowPort, upperPort, Protocol, True)
        #        seclists[hash('oragit-sec-ash1-vnc1-prod-general-1')].addIngressRule('all', lowPort, upperPort, Protocol, True)

        for index, row in enumerate(self.getAllRowsCSV()):
            logging.debug("{} {}".format(index, row))
            # setup the cells
            try:
                protocol = self.__returnProtocol(row[const.PROTO])
            except ValueError as e:
                logging.error(
                    "Found invalid protocol definition {}, in Workbook {}. Skipping row {}.".format(row[const.PROTO],
                                                                                                    self.fileName,
                                                                                                    index + 1))
                continue
            # parse the ports file
            try:
                minPort, maxPort = self.__returnPorts(row[const.MIN], row[const.MAX])
            except ValueError as e:
                logging.error("Found invalid port range {}-{}, in Workbook {}. Skipping row {} ".format(row[const.MIN],
                                                                                                        row[const.MAX],
                                                                                                        self.fileName,
                                                                                                        index + 1))
                continue

            try:
                # EGRESS
                address = self.__nameOrAddress(str(row[const.DSTNAM]), str(row[const.DSTADD]))
                logging.debug(
                    "Egress rule check. {} being used as address for seclist on row with data {}".format(address, row))
                # if the source address is a general address
                if self.__isGeneralSecList(row[const.SRCADD]):
                    logging.debug("Egress rule be in added to general seclist. {}".format(row[const.SRCADD]))
                    # add egress general rule
                    self.__generalSecList(True, row[const.SRCNAM], row[const.SRCADD], row[const.DSTNAM],
                                          row[const.DSTADD], protocol, minPort, maxPort, seclists)
                # elif sourcename is valid
                elif hash(row[const.SRCADD]) in subnets:
                    logging.debug(
                        "Egress rule for subnet {}, to {} on port {}".format(subnets[hash(row[const.SRCADD])].getName(),
                                                                             address,
                                                                             str(minPort) + ":" + str(maxPort)))
                    addresult = subnets[hash(row[const.SRCADD])].addSecListLine(1, address, minPort, maxPort, protocol,
                                                                                True)
                # or subnet is contained sourceaddress
                elif re.search('^10\.15\.', str(row[const.SRCADD])):
                    if hash(row[const.SRCADD]) in subnets:
                        logging.debug("Egress rule for subnet {}, to {} on port {}".format(
                            subnets[hash(str(row[const.SRCNAM]))].getName(), address,
                            str(minPort) + ":" + str(maxPort)))
                        addresult = subnets[hash(row[const.SRCADD])].addSecListLine(1, address, minPort, maxPort,
                                                                                    protocol, True)
                    else:
                        logging.info("Undeployed network {} in port matrix with Security Rule {}".format(row[0], (
                        address, minPort, maxPort, protocol)))
                # INGRESS
                address = self.__nameOrAddress(str(row[const.SRCNAM]), str(row[const.SRCADD]))
                logging.debug(
                    "Ingress rule check. {} being used as address for seclist on row with data {}".format(address, row))
                # if the destinations address is a general address
                if self.__isGeneralSecList(row[const.DSTADD]):
                    logging.debug("Ingress rule be added to general seclist. {}".format(row[const.DSTADD]))
                    # add ingress general rule
                    self.__generalSecList(False, row[const.SRCNAM], row[const.SRCADD], row[const.DSTNAM],
                                          row[const.DSTADD], protocol, minPort, maxPort, seclists)
                # elif sourcename is valid
                elif hash(str(row[const.DSTADD])) in subnets:
                    addresult = subnets[hash(row[const.DSTADD])].addSecListLine(0, address, minPort, maxPort, protocol,
                                                                                True)
                    logging.debug("Ingress rule for subnet {}, to {} on port {}".format(
                        subnets[hash(row[const.DSTADD])].getName(), address, str(minPort) + ":" + str(maxPort)))
                # or subnet is contained sourceaddress
                elif re.search('^10\.15\.', str(row[const.DSTADD])):
                    if hash(row[const.DSTADD]) in subnets:
                        addresult = subnets[hash(row[const.DSTADD])].addSecListLine(0, address, minPort, maxPort,
                                                                                    protocol, True)
                        logging.debug("Ingress rule for subnet {}, to {} on port {}".format(
                            subnets[hash(row[const.DSTADD])].getName(), address, str(minPort) + ":" + str(maxPort)))
                    else:
                        logging.info(
                            "Undeployed network {} in port matrix with Security Rule {}".format(row[const.DSTADD], (
                            address, minPort, maxPort, protocol)))
            except KeyError as e:
                # print "Incorrect subnet hash with data {}".format(row)
                logging.critical(
                    "Incorrect subnet hash with data {} with error {}".format(e, sys.exc_info()[-1].tb_lineno))
                exit(-1)
            logging.debug("End of line {}".format(index))

            # else we skip, implicit

    def getAllRows(self):
        alist = list()
        for index, row in enumerate(self.PMSheet.iter_rows()):
            if index > self.startRow:
                # this row does a validate perhaps create a separate subroutine for this
                if not (row[0].internal_value == None or row[1].internal_value == None or row[
                    2].internal_value == None or row[3].internal_value == None or row[4].internal_value == None or row[
                            5].internal_value == None):
                    sourcename = row[0].internal_value.encode('ascii', errors='ignore').split('\n')
                    sourceaddress = row[1].internal_value.encode('ascii', errors='ignore').split('\n')
                    destinationname = row[2].internal_value.encode('ascii', errors='ignore').split('\n')
                    destinationaddress = row[3].internal_value.encode('ascii', errors='ignore').split('\n')
                    ## need to cover index errors here
                    try:
                        for i in range(0, len(sourcename)):
                            for j in range(0, len(destinationname)):
                                line = (sourcename[i], sourceaddress[i], destinationname[j], destinationaddress[j],
                                        row[4].internal_value.strip(), str(row[5].internal_value).strip())
                                alist.append(line)
                    except IndexError as e:
                        logging.error("Unequal contents at line {}: {} i{},{} j{}".format(index + 1, sourcename, i,
                                                                                          destinationname, j))
                        exit(-1)
        return alist

    def getAllRowsCSV(self):
        alist = list()
        # for index, row in enumerate(self.PMSheet.iter_rows()):
        for index, currentrow in enumerate(self.ws):
            logging.debug("Retrieving row data {}".format(currentrow.strip()))
            row = currentrow.strip().split(',')
            logging.debug("Retrieving row split data {}".format(row))
            if index > self.startRow:
                try:
                    # this row does a validate perhaps create a separate subroutine for this
                    if not (row[const.SOURCENAME] == None or row[const.SOURCEADD] == None or row[
                        const.DESTNAME] == None or row[const.DESTADD] == None or row[const.MINPORT] == None or row[
                                const.MAXPORT] == None or row[const.PROTOCOL] == None):
                        sourcename = row[const.SOURCENAME].encode('ascii', errors='ignore')
                        sourceaddress = row[const.SOURCEADD].encode('ascii', errors='ignore')
                        destinationname = row[const.DESTNAME].encode('ascii', errors='ignore')
                        destinationaddress = row[const.DESTADD].encode('ascii', errors='ignore')
                        # 23 = min port(5), 24 = max port(6), 28 = protocol(7)
                        line = (
                        sourcename, sourceaddress, destinationname, destinationaddress, row[const.MINPORT].strip(),
                        row[const.MAXPORT].strip(), str(row[const.PROTOCOL]).strip())
                        logging.debug("Appending seclist line {} {}".format(type(line), line))
                        alist.append(line)
                except IndexError as e:
                    logging.error("Badly formatted line at {}".format(index))
        return alist

    def getSubnets(self):
        alist = list()
        # iterate through all the rows
        for index, row in enumerate(self.SNSheet.iter_rows()):
            # format is name, ad number, vcn, region, compartment, tenancy,
            # def __init__(self, Name, DisplayName,Region,CIDR,Compartment,VCN)
            if not (row[0].internal_value == None or row[1].internal_value == None or row[2].internal_value == None or
                    row[3].internal_value == None or row[4].internal_value == None or row[5].internal_value == None):
                addresses = str(row[1].internal_value).split('\n') + str(row[3].internal_value).split('\n')
                for line in addresses:
                    if not ipFormatCheck(line.strip()):
                        raise ValueError("Invalid IP address on line " + str(index + 1) + " " + line + str(row))
                if not isPortRange(row[5].internal_value):
                    raise ValueError("Invalid port range on line " + str(index + 1))
                alist.append(row)
            elif index > self.startRow and not (
                    row[0].internal_value == None or row[1].internal_value == None or row[2].internal_value == None or
                    row[3].internal_value == None or row[4].internal_value == None or row[5].internal_value == None):
                raise ValueError("Invalid data on row " + str(index + 1))
        return alist

    def getNextRow(self):
        alist = list()
        self.currentRow = self.currentRow + 1
        for i in 'abcdef':
            cell = i + int(self.currentRow)
            alist.append = self.PMSheet[cell].internal_value
        return alist

    def getCell(self, cell):
        if re.search('\w+\d+'):
            return self.PMSheet[cell]
        else:
            return None

    def getChanges(self):
        returnstring = list()
        version = self.getVersion()
        for index, row in enumerate(self.PMSheet.iter_rows()):
            if re.search(str(version), str(row[7].internal_value)):
                # print index+1,
                # for i in range(0,5):
                #    print str(row[i].internal_value).split(),
                # print
                templist = list()
                templist.append(index + 1)
                for i in range(0, 5):
                    templist.append(str(row[i].internal_value).split())
                returnstring.append(templist)
        return returnstring

    def getVersion(self):
        return self.PMSheet['E5'].internal_value


# END OF PortMatrix

# detects an oragitnet address
def isORAGITnet(string):
    string = string.strip()
    if re.search('^oragit-(ash|phx)1-net-vcn1-ad[1-3]-prod-ngcc-*$', string):
        return True
    return False


# net to sec value
def convertTosec(string):
    match = re.match('^(oragit-)(ash|phx)(\d-)net-(vcn1-)ad[1-3]-(.*)$', string)
    return match.group(1) + match.group(2) + match.group(3) + "sec-" + match.group(4) + match.group(5)


# converts all adX addresses to AD1
def mashSubnetName(subnetName):
    matches = re.search('^(oragit-)(ash|phx)(\d-net-vcn1-ad)[1-3](.*)$', subnetName)
    if matches:
        return matches.group(1) + matches.group(2) + matches.group(3) + '1' + matches.group(4)
    else:
        return None


# from a net address, returns the region (phoenix or ashburn)
def returnRegionFromName(subnetName):
    matches = re.search('^oragit-(ash|phx)(\d+)-net-vcn1-ad[1-3].*$', subnetName)
    if matches:
        return matches.group(1) + matches.group(2)
    else:
        return None


# getting a multiline value and responding (this is due to excel spreadsheet cells with multiline addresses and networks)
def returnAddressesFromString(subnetString):
    return subnetString.split('\n')


def ipFormatCheck(ip_str):
    pattern = r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    if re.match(pattern, ip_str):
        return True
    else:
        return False


def setLogging(logfilename, loglevel):
    if os.path.exists(logfilename):
        os.remove(logfilename)
    log = logging.CRITICAL
    if loglevel > 4:
        log = logging.DEBUG
    elif loglevel == 4:
        log = logging.INFO
    elif loglevel == 3:
        log = logging.WARNING
    elif loglevel == 2:
        log = logging.ERROR
    elif loglevel == 1:
        loglevel = logging.CRITICAL
    logging.basicConfig(filename=logfilename, level=log, format='%(asctime)s: %(levelname)s : %(funcName)s %(message)s')
    logging.critical('Started Logging at level {}'.format(loglevel))


if __name__ == '__main__':

    # const.MAXRULE = 50
    const.STARTROW = 6
    const.NETSTARTROW = 0

    parser = argparse.ArgumentParser(description='Creates blank subnet and seclist files')
    parser.add_argument("-s", help="Excel Port Matrix", type=str, metavar="<seclist spreadsheet>", )
    parser.add_argument("-r", help="Switches on rules number listing", action="store_true", dest="rules", default=False)
    parser.add_argument("-n", help="Excel Port Matrix Network file ", metavar="<Subnet List spreadsheet>")
    parser.add_argument("-o", help="Outputs files, otherwise just processes the spreadsheet", action="store_true",
                        dest="output", default=False)
    parser.add_argument("-p", help="Prints contents to terminal", action="store_true", dest="prints", default=False)
    parser.add_argument("-V", help="Prints out versioning information", action='store_true', dest="version",
                        default=False)
    parser.add_argument("-v", help="Set debugging level", action='count', default=3)
    args = parser.parse_args()

    pmlist = list()
    # do we want to be able to just have critical only, or just add on to error?
    setLogging('sec_build_v{}.{}.log'.format(majorVersion, minorVersion), args.v)

    if args.version:
        print ("sec Build Version: {0}.{1}.{2}".format(majorVersion, minorVersion, patchVersion))
        index = 0
        if args.s:
            for item in args.s:
                match = re.search("(.*):(.*)", item[0])
                portmatrixfile = match.group(1)
                portmatrixsheet = match.group(2)
                pmlist.append(PortMatrix(portmatrixfile, const.STARTROW, portmatrixsheet))
                print ("Port Matrix {} Version: {}".format(portmatrixfile, pmlist[index].getVersion()))
                index = index + 1
        exit(0)

    elif args.s:
        # we need to have a network file at this point so fail if not there
        if not args.n:
            print ("Need to declare a network file")
            exit(0)
        ##        #Load networks section, uses <file>:<sheet> This is no longer needed with the CSV version
        ##        matchstr = re.search(r"^(.*):(.*)$",args.n)
        ##        networkfile = matchstr.group(1)
        ##        networksheet = matchstr.group(2)
        ##        subnetfile = SubnetFile(networkfile, const.NETSTARTROW, networksheet)
        subnetfile = SubnetFile(args.n, const.NETSTARTROW)

        # seclist uses <file>:<sheet>
        logging.debug("Adding files {}".format(args.s))
        # for item in args.s:
        # match = re.search("(.*)",item[0])
        portmatrixfile = args.s.strip()
        # portmatrixsheet = match.group(2)
        logging.info("Processing file {}".format(portmatrixfile))
        pmlist.append(PortMatrix(portmatrixfile, 1))

        # list of subnets
        subnets = dict()

        # general list of seclists to be added to by the subnets
        seclists = dict()

        # Add the two special cases for each region
        logging.debug('Setting up general seclists')
        seclists[hash('oragit-sec-phx1-vnc1-prod-general-1')] = SecList('oragit-sec-phx1-vnc1-prod-general-1',
                                                                        'oragit-sec-phx1-vnc1-prod-general-1', 'phx1')
        seclists[hash('oragit-sec-phx1-vnc1-prod-general-2')] = SecList('oragit-sec-phx1-vnc1-prod-general-2',
                                                                        'oragit-sec-phx1-vnc1-prod-general-2', 'phx1')
        seclists[hash('oragit-sec-ash1-vcn1-prod-general-1')] = SecList('oragit-sec-ash1-vcn1-prod-general-1',
                                                                        'oragit-sec-ash1-vcn1-prod-general-1', 'ash1')
        seclists[hash('oragit-sec-ash1-vcn1-prod-general-2')] = SecList('oragit-sec-ash1-vcn1-prod-general-2',
                                                                        'oragit-sec-ash1-vcn1-prod-general-2', 'ash1')
        seclists[hash('oragit-sec-fra1-vcn1-prod-general-1')] = SecList('oragit-sec-fra1-vcn1-prod-general-1',
                                                                        'oragit-sec-fra1-vcn1-prod-general-1', 'fra1')
        seclists[hash('oragit-sec-fra1-vcn1-prod-general-2')] = SecList('oragit-sec-fra1-vcn1-prod-general-2',
                                                                        'oragit-sec-fra1-vcn1-prod-general-2', 'fra1')

        # collect all the known subnets in the tenancy
        subnetfile.addToList(subnets, seclists)

        for spreadsheet in pmlist:
            spreadsheet.addToConfig(subnets, seclists)

        # now we go through the list and produce some output
        for key in subnets:
            if isinstance(subnets[key], Subnet):
                subnetname = subnets[key].getName()
                logging.debug(
                    "Retrieved key {} for subnet {}, cidr {}".format(key, subnetname, hash(subnets[key].getCidr())))
                if args.output or args.prints or args.rules: print ("*Start of {}".format(subnetname))
                if args.output:
                    logging.debug("Writing: {}".format(subnetname))
                    ofile = open(subnetname + ".tf", 'w')
                    ofile.write(subnets[key].outputSubnetFile() + "\n")
                    ofile.close()
                if args.prints:
                    print ("Printing: {}".format(subnetname))
                    print (subnets[key].outputSubnetFile())
                if args.rules == True: print (subnets[key].rulesUsed())
                if args.output or args.prints or args.rules: print ("*End of {0}\n".format(subnets[key].getName()))

        for key in seclists:
            if args.output or args.prints: print ("*Start of {0}".format(seclists[key].getName()))
            seclistname = seclists[key].getName()
            if args.output:
                logging.debug("Writing: {}".format(seclistname))
                ofile = open(seclistname + ".tf", 'w')
                ofile.write(seclists[key].outputSecList() + "\n")
                ofile.close()

            if args.prints:
                print ("Printing: {}".format(seclistname))
                print (seclists[key].outputSecList())
            if args.output or args.prints: print ("*End of {0}\n".format(seclistname))

        # if args.changes:
        #    pass
        # for spreadsheet in pmlist:
        #    changes = spreadsheet.getChanges()
        #    for change in changes:
        #        print "Changes are {0}".format(change)

        print ("Number of rows found: {0} for networks".format(len(subnets)))
        print ("Number of seclists created: {0}".format(len(seclists)))

    # elif args.deduplication:
    #    print "Cannot deduplicate without an Port Matrix file"
    #    exit(0)

    # TODO and now we need to mess around with file names and some bits of contents
    # phx general is vnc not vcn
    # blackchair is an old style subnet
    # -- others add stuff here
    # oragit-phx1-net-vcn1-ad1-dev-tools-em13-internal-mt1
    # oragit-phx1-net-vcn1-ad1-prod-tools-bastion-internal-mt1
    # looks like a lot of phx1 ashburn

    logging.critical('Stopped logging')