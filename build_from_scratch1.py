#!/usr/bin/python
# Name: Build_From_Scratch.py
majorVersion = 1
minorVersion = 1
patchVersion = 'a'

"""NOTES
This is the build from scratch file. It takes output from GCSDT and provides terraform files for deployment into OCI
"""
# TODO
# summarisation of ports and subnets
# Alter input to take new column for the transport layer protocol

# Set log level here for the library 1 = CRIT, 5 = DEBUG, 0 = OFF
# Set to OFF(0) when not doing debug or development
# loglevel = 4

# tenancy = "sandbox" # sandbox or prod
# from openpyxl import Workbook, load_workbook
# import re
import argparse
import os
import logging
# import sys
# import traceback
# import ipaddress
# import json
# import csv
from pathlib import Path
import time
import configparser
# import const

# import const

from oci.OCI_SecListRule import SecListRule
from oci.OCI_Seclist import SecList
from oci.OCI_Subnet import Subnet
from csdt.subnet_file import SubnetFile
from csdt.portmatrix_file import PortMatrix
from bfs.bfs import BuildFromScratch
from oci.ORAGIT_elements import const


# logfilename = "Build_From_Scratch.log"

# from oci_summarisation import egress_duplicate_summarisation, ingress_duplication_summarization

# class SubnetFile:
#     '''
#     This class is the connection to a network csv file with lists of all the networks to be built.
#     networks are removed by not being included in these files
#     '''
#     def __init__(self, filename, startrow):
#         self.logger = logging.getLogger("{}.SubnetFile".format(__name__))
#         self.logger.info("Logging started for SubnetFile")
#         self.columns = dict()
#         # network file fields
#         #self.columns["NETSUBNETNAME"] = const.NETSUBNETNAME #0
#         #self.columns["NETLONGNAME"] = const.NETLONGNAME #1
#         #self.columns["NETJIRA"] = const.NETJIRA #2 not used!
#         #self.columns["NETOCID"] = const.NETOCID #3 not used!
#         #self.columns["NETCIDR"] = const.NETCIDR #4
#         #self.columns["NETSUFFIX"] = const.NETSUFFIX #5 not used!
#         #self.columns["NETEXTERNAL"] = const.NETEXTERNAL #6 not used!
#         #self.columns["NETREGION"] = const.NETREGION #7
#         #self.columns["NETCOMPARTMENT"] = const.NETCOMPARTMENT #8
#         #self.columns["NETHIDDENDOMAIN"] = const.NETHIDDENDOMAIN #9 not used!
#         #self.columns["NETCOMPARTMENTOCID"] = const.NETCOMPARTMENTOCID #10 not used!
#         #self.columns["NETSTATUS"] = const.NETSTATUS #11 not used!
#         #self.columns["NETAD"] = const.NETAD #12
#         #self.columns["NETVCN"] = const.NETVCN #13
#         #self.columns["NETDNSLABEL"] = const.NETDNSLABEL #14 not really used
#         #self.columns["NETDHCPDNS1"] = const.NETDHCPDNS1 #15 not really used
#         #self.columns["NETDHCPDNS2"] = const.NETDHCPDNS2 #16 not really used
#         #self.columns["NETDHCPDNS3"] = const.NETDHCPDNS3 #17 not really used

#         try:
#             # if we've defined this then we must have some data else forget it
#             if filename is not None:
#                 self.ws = open(filename, 'r')
#                 #Read 1st line and derive column ids from it
#                 header_line = self.ws.readline().split(",")
#                 #print(header_line)
#                 for (idx,header) in enumerate(header_line):
#                     header = header.replace("\"","").strip()
#                     for (key,value) in const.NETCOLUMNSMAP.items():
#                         if header == value:
#                             self.columns[key] = idx

#                 self.logger.info('Columns detected in subnet file')
#                 self.logger.debug('Detected column map: {}'.format(self.columns))
#         except IOError as e:
#             print ("Unable to open the Subnet file {0}: {1}".format(filename, e))
#             self.logger.critical("Unable to open the Subnet file {0}: {1}".format(filename, e))
#             exit(0)
#         #may not need the following line, it was used in the past to catch corrupted files
#         except Exception as e:
#             print ("File corrupted {0}".format(e))
#             self.logger.critical("File corrupted {0}".format(e))
#             exit(0)
#         else:
#             # We close the file at this point as it resets the reading position
#             self.filename = filename
#             self.ws.close()


#     def __ipFormatCheck(self, ip_str):
#         pattern = r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([1-2]?\d|3[0-2])"
#         if re.match(pattern, ip_str):
#           return True
#         else:
#           return False
#     def isValidOCICIDRBlock(self, cidr_block):
#         try:
#             subnet_block = ipaddress.ip_network(cidr_block)

#         except:

#                 return False
#         else:
#             if subnet_block.version != 4:
#                 #Not an IPv4 block
#                 return False
#             if subnet_block.prefixlen < 16 or subnet_block.prefixlen > 30:
#                 #Not an accepted size. Must be between [16-30]
#                 return False
#             return True

#     def __checkRegion(self,region_code):
#         if region_code in const.REGIONCODES:
#             return True
#         else:
#             return False


#     def __checkAD(self, region_code, ad_name):
#         if ad_name in const.REGIONAD[region_code]:
#             return True
#         else:
#             return False


#     def __getAD_id(self, region_code, ad_name):
#         if self.__checkAD(region_code, ad_name):
#             m = re.search('([0-9]+)$',ad_name)
#             if not m is None:
#                 return m.group(0)
#         return 0

#     def __checkVCN(self, region_code, vcn_name):
#         if vcn_name in const.REGIONVCN[region_code]:
#             return True
#         else:
#             return False


#     def __getVCN_id(self, region_code, vcn_name):
#         if self.__checkVCN(region_code, vcn_name):
#             m = re.search('([0-9]+)$',vcn_name)
#             if not m is None:
#                 return m.group(0)
#         return 0


#     #takes a dictionary and adds subnets to it
#     #def addToList(self, subnets, seclists):
#     #    """
#     #    Adds all the networks to subnets and seclists dictionaries from this SubnetFile object
#     #    """
#     #    # self.logger = logging.getLogger("sec_build_v5.SubnetFile")
#     #    # self.logger.critical("Logging started for SubnetFile")
#     #    alist = self.getSubnetsFromCSV()
#     #    self.logger.info("Number of rows returned from {} is {}".format(self.filename,len(alist)))
#     #    index = 0
#     #    for row in alist:
#     #        index = index + 1
#     #        # create a temporary subnet before we add it to the list
#     #        temp_subnet = Subnet(
#     #            Name = row[0],
#     #            DisplayName = row[1],
#     #            Region = row[2],
#     #            CIDR = row[3],
#     #            Compartment = row[4],
#     #            AD = row[5],
#     #            VCN = row[6],
#     #            dhcpOptions = row[7],
#     #            dhcpDNS1 = row[8],
#     #            dhcpDNS2 = row[9],
#     #            dhcpDNS3 = row[10],
#     #            dnsLabel = row[11],
#     #            dnsType = row[12],
#     #            #Aren't we sending too many seclists in or is this empty?
#     #            seclists = seclists)
#     #        # do we have any duplicate subnet declarations, send error to logs if we do
#     #        if hash(row[3]) not in subnets:
#     #            subnets[hash(row[3])] = temp_subnet
#     #        else:
#     #            self.logger.error("Duplicate subnet for network {}".format(row[3]))
#     #        self.logger.debug("Adding subnet #{}[{}] with CIDR {} and hash {}".format(index, row[0], row[3], hash(row[3])))
#     #    return len(alist)

#     def getSubnetsFromCSV(self, seclists):
#         """
#         The function returns a dict of lists of all the rows in the subnet file
#         The list of the fields is set out in the const.NET* variables at the top of the file
#         ## 2018-05-28 List of fields is auto-detected in __init__
#         """
#         self.ws = open(self.filename, 'r')
#         reader = csv.reader(self.ws, delimiter=',')
#         subnets_dict = dict()
#         print ("Loading subnets...")
#         index = 0
#         for row in reader:
#             index = index + 1
#             '''we do a check just to make sure none of the values are blank, otherwise fail this line'''
#             pattern = re.compile("None|-|TBD")
#             if index > const.NETSTARTROW:
#                 if pattern.match(row[self.columns["NETSUBNETNAME"]]):
#                     self.logger.error("Invalid NETSUBNETNAME '{}' in row {}".format(row[self.columns["NETSUBNETNAME"]], index))
#                     print("_", end='')
#                     continue
#                 elif pattern.match(row[self.columns["NETLONGNAME"]]):
#                     self.logger.error("Invalid NETLONGNAME '{}' in row {} [{}]".format(row[self.columns["NETLONGNAME"]], index, row[self.columns["NETSUBNETNAME"]]))
#                     print("_", end='')
#                     continue
#                 elif pattern.match(row[self.columns["NETCIDR"]]):
#                     self.logger.error("Invalid NETCIDR '{}' in row {} [{}]".format(row[self.columns["NETCIDR"]], index, row[self.columns["NETSUBNETNAME"]]))
#                     print("_", end='')
#                     continue
#                 elif pattern.match(row[self.columns["NETREGION"]]):
#                     self.logger.error("Invalid NETREGION '{}' in row {} [{}:{}]".format(row[self.columns["NETREGION"]], index, row[self.columns["NETSUBNETNAME"]], row[self.columns["NETCIDR"]]))
#                     print("_", end='')
#                     continue
#                 elif pattern.match(row[self.columns["NETCOMPARTMENT"]]):
#                     self.logger.error("Invalid NETCOMPARTMENT '{}' in row {} [{}:{}]".format(row[self.columns["NETCOMPARTMENT"]], index, row[self.columns["NETSUBNETNAME"]], row[self.columns["NETCIDR"]]))
#                     print("_", end='')
#                     continue
#                 elif pattern.match(row[self.columns["NETAD"]]):
#                     self.logger.error("Invalid NETAD '{}' in row {} [{}:{}]".format(row[self.columns["NETAD"]], index, row[self.columns["NETSUBNETNAME"]], row[self.columns["NETCIDR"]]))
#                     print("_", end='')
#                     continue
#                 elif pattern.match(row[self.columns["NETVCN"]]):
#                     self.logger.error("Invalid NETVCN '{}' in row {} [{}:{}]".format(row[self.columns["NETVCN"]], index, row[self.columns["NETSUBNETNAME"]], row[self.columns["NETCIDR"]]))
#                     print("_", end='')
#                     continue
#                 elif not self.__ipFormatCheck(row[self.columns["NETCIDR"]]):
#                     self.logger.error("Invalid CIDR address format '{}' in row {} [{}:{}]".format(row[self.columns["NETCIDR"]], index, row[self.columns["NETSUBNETNAME"]], row[self.columns["NETCIDR"]]))
#                     print("_", end='')
#                     continue
#                 elif not self.__checkRegion(row[self.columns["NETREGIONCODE"]]):
#                     self.logger.error("Invalid NETREGIONCODE format '{}' in row {} [{}:{}]".format(row[self.columns["NETREGIONCODE"]], index, row[self.columns["NETSUBNETNAME"]], row[self.columns["NETCIDR"]]))
#                     print("_", end='')
#                     continue
#                 elif  self.__getAD_id(row[self.columns["NETREGIONCODE"]],row[self.columns["NETAD"]]) == 0:
#                     self.logger.error("Invalid NETAD format '{}' in row {} [{}:{}]".format(row[self.columns["NETAD"]], index, row[self.columns["NETSUBNETNAME"]], row[self.columns["NETCIDR"]]))
#                     print("_", end='')
#                     continue
#                 elif  self.__getVCN_id(row[self.columns["NETREGIONCODE"]],row[self.columns["NETVCN"]]) == 0:
#                     self.logger.error("Invalid NETVCN format '{}' in row {} [{}:{}]".format(row[self.columns["NETVCN"]], index, row[self.columns["NETSUBNETNAME"]], row[self.columns["NETCIDR"]]))
#                     print("_", end='')
#                     continue

#                 subnet = str(row[self.columns["NETCIDR"]]).strip()
#                 # 2018-05-28 - Region assigned to region code

#                 region = row[self.columns["NETREGIONCODE"]]
#                 # we only use the numeric suffix of the NETAD and NETVCN value. They have already been checked for validity.
#                 ad = self.__getAD_id(row[self.columns["NETREGIONCODE"]], row[self.columns["NETAD"]])
#                 vcn = self.__getVCN_id(row[self.columns["NETREGIONCODE"]], row[self.columns["NETVCN"]])

#                 # In lhr1 we use a new template, so therefore we use a different set of dhcp options.
#                 # 2018-05-29: These 2 look the same. Do we really need the if clause?
#                 dhcpOptions = ''
#                 # For regions using old DHCP Options, create the dhcpOptions string:
#                 if region in const.DHCPREGIONS:
#                     dhcpOptions = "oragit-{region}-dhcp1".format(region = region)

#                 #print(row[self.columns["NETDHCPOPTIONS"]])
#                 dns_servers = [None,None,None]
#                 dns_server_type = "VcnLocalPlusInternet"
#                 try:
#                     dhcp_options = json.loads(row[self.columns["NETDHCPOPTIONS"]])
#                 except Exception as e:
#                     self.logger.error("Incorrectly formatted DHCP Options '{}' in row {} [{}:{}]".format(row[self.columns["NETDHCPOPTIONS"]], index, row[self.columns["NETSUBNETNAME"]], row[self.columns["NETCIDR"]]))
#                     print("_", end='')
#                     continue
#                 else:
#                     self.logger.debug("DHCP Options detected on row {}:'{}'".format(index,json.dumps(dhcp_options)))
#                     dns_server_type = dhcp_options[0]["server-type"]
#                     if dns_server_type == 'CustomDnsServer':
#                         dns_servers = dhcp_options[0]["custom-dns-servers"]
#                         for i in range (len(dns_servers),3):
#                             dns_servers.append(None)
#                     elif dns_server_type == 'VcnLocalPlusInternet':
#                         #Nothing to do for now..
#                         pass
#                     else:
#                         self.logger.error("Invalid DHCP Server Type format '{}' in row {} [{}:{}]".format(dns_server_type, index, row[self.columns["NETSUBNETNAME"]], row[self.columns["NETCIDR"]]))
#                         print("_", end='')
#                         continue
#                 #alist.append(
#                 #    (
#                 #        row[self.columns["NETSUBNETNAME"]],
#                 #        row[self.columns["NETSUBNETNAME"]],
#                 #        region,
#                 #        subnet,
#                 #        row[self.columns["NETCOMPARTMENT"]],
#                 #        ad,
#                 #        vcn,
#                 #        dhcpOptions,
#                 #        dns_servers[0],
#                 #        dns_servers[1],
#                 #        dns_servers[2],
#                 #        row[self.columns["NETDNSLABEL"]],
#                 #        dns_server_type
#                 #        )
#                 #    )
#                 print("#", end='')
#                 if hash(subnet) in subnets_dict.keys():
#                     self.logger.error("Duplicate hash '{}' in row {} [{}:{}])".format(hash(subnet), index, row[self.columns["NETSUBNETNAME"]], row[self.columns["NETCIDR"]]))
#                 else:
#                     subnets_dict[hash(subnet)] = Subnet(
#                         Name = row[self.columns["NETSUBNETNAME"]],
#                         DisplayName = row[self.columns["NETSUBNETNAME"]],
#                         Region = region,
#                         CIDR = subnet,
#                         Compartment = row[self.columns["NETCOMPARTMENT"]],
#                         AD = ad,
#                         VCN = vcn,
#                         dhcpOptions = dhcpOptions,
#                         dhcpDNS1 = dns_servers[0],
#                         dhcpDNS2 = dns_servers[1],
#                         dhcpDNS3 = dns_servers[2],
#                         dnsLabel = row[self.columns["NETDNSLABEL"]],
#                         dnsType = dns_server_type,
#                         seclists = seclists)
#                 logger.info("Successfully added subnet {}:{} from row {}".format(row[self.columns["NETSUBNETNAME"]], subnet, index))
#             else:
#                 if index > const.NETSTARTROW:
#                     logger.error( "Unable to add subnet from row {}".format(index))
#         # We should always close the file once finished with it
#         self.ws.close()
#         print ("\nLoaded {} subnets out of {} lines".format(len(subnets_dict.keys()),index))
#         # And return the list of values we've taken from the network file
#         #return alist
#         return subnets_dict
# END OF SubnetFile

# This class was originally built just to take in the Port Matrix elements
# It can now take in a subnet spreadsheet, that could be separate or in the same files
# class PortMatrix:
#     """
#     This imports port matricies into the system from CSV files from GCSDT.
#     """
#     def __init__(self, filename, startrow):
#         self.logger = logging.getLogger("{}.PortMatrix".format(__name__))
#         self.logger.log(60,"Logging started for PortMatrix")
#         self.fileName = filename
#         self.startRow = startrow
#         self.columns = dict()
#         # self.columns['SECSRCNAME'] = const.SRCNAM
#         # self.columns['SECSRCADDR'] = const.SRCADD
#         # self.columns['SECDSTNAME'] = const.DSTNAM
#         # self.columns['SECDSTADDR'] = const.DSTADD
#         # self.columns['SECMINPORT'] = const.MINPORT
#         # self.columns['SECMAXPORT'] = const.MAX
#         # self.columns['SECPROTOCOL'] = const.PROTO
#         try:
#             self.ws = open(self.fileName, 'r') # throw an error is unable to open the file
#         except IOError as e:
#             print ("Unable to open the Port Matrix file {0}: {1}".format(filename, e))
#             exit(0)
#         #except BadZipfile as e:
#         #    print "File corrupted {0}".format(e)
#         #    exit(0)
#         except Exception as e:
#             print (e)
#             exit(0)
#         else:
#             #This has already been intiated at the beginning.
#             self.currentRow = 0
#             self.startRow = startrow
#             #self.PMSheet = self.ws[pmsheet]
#             #TODO perhaps keep a cached version of the spreadsheet worksheet
#             #self.wsseclist = getAllRows()
#             header_line = self.ws.readline().split(",")
#                 #print(header_line)
#             for (idx,header) in enumerate(header_line):
#                 header = header.replace("\"","").strip()
#                 for (key,value) in const.AUDITCOLUMNSMAP.items():
#                     if header == value:
#                         self.columns[key] = idx


#     #net to cidr address
#     def __convertTocidr(self, subnet_name):
#             #match = re.match(r'^(oragit-)(ash|phx|fra)(\d-)net-(vcn1-ad[1-3]-.*)$',string)
#             #if match:
#             #    return match.group(1)+match.group(2)+match.group(3)+"cidr-"+match.group(4)
#             #else: return False
#             tenancy_pattern = const.TENANCIES.join("|")
#             region_pattern = const.REGIONCODES.join("|")
#             vcn_pattern = 'vcn1'
#             ad_pattern = 'ad[1-3]'
#             subnet_pattern = '^'+tenancy_pattern+'-'+region_pattern+'-net-'+'-'+vcn_pattern+'-'+ad_pattern+'-'+'.*$'
#             if re.match(subnet_pattern, subnet_name):
#                 return string.replace('-net-','-cidr-',1)
#             return ""

#     #set of utility functions for crafting elements
#     def __isPortRange(self,stringIN):
#         stringF = str(stringIN).strip()
#         #is the cell containing either 1 number or two number separated by a dash or Any:Any
#         if re.search(r'^\d{1,5}(-\d{1,5})?$',stringF) or re.search(r'^all$',stringF):
#             return True
#         #raise ValueError("Invalid Port {0}".format(stringIN))
#         return False

#     def __generalSecList(self, Direction, sname, sipaddress, dname, dipaddress, Protocol, minport, maxport, seclist,
#                          subnet):
#         """
#         This adds rules into the general seclists. It's a fudge script requiring code alteration with new regions
#         :param Direction: True = Egress, False = Ingress, bool
#         :param sname: source name of the rule, str
#         :param sipaddress: source ip address of the rule, str
#         :param dname:  destination name of the rule ,str
#         :param dipaddress: destination ip address of the rule, str
#         :param Protocol: layer 4 protocol valid entries are tcp/udp/icmp/all, str
#         :param minport: lowest port for the rule, int
#         :param maxport: highest port for the rule, int
#         :param seclist: a pointer to the seclist list
#         :return:
#         """
#         # TODO Fix the general seclists so that we don't have to alter the script for new regions
#         #try:
#         #    lowPort, upperPort = self.__returnPorts(minport,maxport)
#         #except:
#         #    self.logger.error("Found invalid port range {}-{}, skipping row".format(minport, maxport))
#         lowPort = minport
#         upperPort = maxport
#         if Direction:
#             # phoenix egress
#             address = self.__nameOrAddress(dname,dipaddress, subnet)
#             if sipaddress == '10.15.0.0/16' or sipaddress == '10.15.0.0/17' or sipaddress == '10.15.0.0/18':
#                 if seclist[hash('oragit-phx1-sec-vnc1-prod-general')].numOfEgress() < const.MAXRULE * const.GENSECLIST:
#                     self.logger.debug("Adding egress rule {} to {}".format(
#                         seclist[hash('oragit-phx1-sec-vnc1-prod-general')].numOfEgress(),
#                         'oragit-phx1-sec-vnc1-prod-general'))
#                     seclist[hash('oragit-phx1-sec-vnc1-prod-general')].addEgressRule(address, lowPort, upperPort,
#                                                                                      Protocol, True)
#                 else:
#                     self.logger.critical("Too many Egress rules on Pheonix")
#             # ashburn egress
#             if sipaddress == '10.15.0.0/16' or sipaddress == '10.15.0.0/17' or sipaddress == '10.15.64.0/18':
#                 if seclist[hash('oragit-ash1-sec-vnc1-prod-general')].numOfEgress() < const.MAXRULE * const.GENSECLIST:
#                     self.logger.debug("Adding egress rule {} to {}".format(
#                         seclist[hash('oragit-ash1-sec-vnc1-prod-general')].numOfEgress(),
#                         'oragit-ash1-sec-vnc1-prod-general'))
#                     seclist[hash('oragit-ash1-sec-vnc1-prod-general')].addEgressRule(address, lowPort, upperPort,
#                                                                                      Protocol, True)
#                 else:
#                     self.logger.critical("Too many Egress rules on Ashburn")
#             # frankfurt egress
#             if sipaddress == '10.15.0.0/16' or sipaddress == '10.15.128.0/18' or sipaddress == '10.15.160.0/19':
#                 if seclist[hash(const.SECLISTGENERALFRA)].numOfEgress() < const.MAXRULE * const.GENSECLIST:
#                     self.logger.debug("Adding egress rule {} to {}".format(
#                         seclist[hash(const.SECLISTGENERALFRA)].numOfEgress(), const.SECLISTGENERALFRA))
#                     seclist[hash(const.SECLISTGENERALFRA)].addEgressRule(address, lowPort, upperPort, Protocol, True)
#                 else:
#                     self.logger.critical("Too many Egress rules on Frankfurt")
#             # London egress
#             if sipaddress == '10.15.0.0/16' or sipaddress == '10.15.128.0/18' or sipaddress == const.SECLISTGENERALCIDRLHR:
#                 if seclist[hash(const.SECLISTGENERALLHR)].numOfEgress() < const.MAXRULE * const.GENSECLIST:
#                     self.logger.debug("Adding egress rule {} to {}".format(
#                         seclist[hash(const.SECLISTGENERALLHR)].numOfEgress(), const.SECLISTGENERALLHR))
#                     seclist[hash(const.SECLISTGENERALLHR)].addEgressRule(address, lowPort, upperPort, Protocol, True)
#                 else:
#                     self.logger.critical("Too many Egress rules on Heathrow")
#         else:
#             # Phoenix ingress
#             address = self.__nameOrAddress(sname,sipaddress, subnet)
#             if dipaddress == '10.15.0.0/16' or dipaddress == '10.15.0.0/17' or dipaddress == '10.15.0.0/18':
#                 if seclist[hash('oragit-phx1-sec-vnc1-prod-general')].numOfIngress() < const.MAXRULE * const.GENSECLIST:
#                     self.logger.debug("Adding ingress rule {} to {}".format(
#                         seclist[hash('oragit-phx1-sec-vnc1-prod-general')].numOfIngress(),
#                         'oragit-phx1-sec-vnc1-prod-general-1'))
#                     seclist[hash('oragit-phx1-sec-vnc1-prod-general')].addIngressRule(address, lowPort, upperPort, Protocol, True)
#                 else:
#                     self.logger.critical("Too many Ingress rules on Pheonix")
#             # Ashburn ingress
#             if dipaddress == '10.15.0.0/16' or dipaddress == '10.15.0.0/17' or dipaddress == '10.15.64.0/18':
#                 if seclist[hash('oragit-ash1-sec-vnc1-prod-general')].numOfIngress() < const.MAXRULE * const.GENSECLIST:
#                     self.logger.debug("Adding ingress rule {} to {}".format(
#                         seclist[hash('oragit-ash1-sec-vnc1-prod-general')].numOfIngress(),
#                         'oragit-ash1-sec-vnc1-prod-general'))
#                     seclist[hash('oragit-ash1-sec-vnc1-prod-general')].addIngressRule(address, lowPort, upperPort,
#                                                                                       Protocol, True)
#                 else:
#                     self.logger.critical("Too many Ingress rules on Ashburn")
#             # Frankfurt ingress
#             if dipaddress == '10.15.0.0/16' or dipaddress == '10.15.128.0/18' or dipaddress == '10.15.160.0/19':
#                 if seclist[hash(
#                         const.SECLISTGENERALFRA)].numOfIngress() < const.MAXRULE * const.GENSECLIST:
#                     self.logger.debug("Adding ingress rule {} to {}".format(
#                         seclist[hash(const.SECLISTGENERALFRA)].numOfIngress(),
#                         const.SECLISTGENERALFRA))
#                     seclist[hash(const.SECLISTGENERALFRA)].addIngressRule(address, lowPort,
#                                                                                       upperPort, Protocol, True)
#                 else:
#                     self.logger.critical("Too many Ingress rules on Frankfurt")
#             # London ingress
#             if dipaddress == '10.15.0.0/16' or dipaddress == '10.15.128.0/18' or dipaddress == const.SECLISTGENERALCIDRLHR:
#                 if seclist[hash(
#                         const.SECLISTGENERALLHR)].numOfIngress() < const.MAXRULE * const.GENSECLIST:
#                     self.logger.debug("Adding ingress rule {} to {}".format(
#                         seclist[hash(const.SECLISTGENERALLHR)].numOfIngress(),const.SECLISTGENERALLHR))
#                     seclist[hash(const.SECLISTGENERALLHR)].addIngressRule(address, lowPort, upperPort, Protocol, True)
#                 else:
#                     self.logger.critical("Too many Ingress rules on Heathrow")


#     def __isGeneralSecList(self, line):
#         """
#         This function test to see if the input string conforms to being one of the defined general subnet summarizations
#         :param line: a string that should be a cidr mechanism
#         :return: boolean
#         """
#         # TODO perhaps we should turn the general seclists into some kind of overloaded seclist with check functions
#         #general_lists = ('10.15.0.0/16', '10.15.0.0/17', '10.15.0.0/18', '10.15.64.0/18','10.15.128.0/18',
#         #                 const.SECLISTGENERALCIDRLHR, '10.15.160.0/19')
#         general_lists = const.VCNRANGE.values()
#         print(general_lists)
#         #address = line
#         #for a in general_lists:
#         #    if a == address:
#         #        logger.debug("Found general seclist {} address".format(line))
#         #        return True
#         #return False
#         if line in general_lists:
#             return True
#         logger.debug("Found general seclist {} address".format(line))
#         return True

#     """ This will figure out which of and address or ip address to use. If the subnet name starts with oragit it
#     presumes use the name
#     It also chose which which pair to look at depending on the line value, which needs to be calculated by the calling
#     code
#     If the line exceeds the number of lines in the corresponding choice, it defaults to the first one
#     finally if a it is an IP address it makes sure there is a valid CIDR suffix attached, otherwise sets it to /32
#     """
#     #TODO I don't think this is working needs a fix
#     def __nameOrAddress(self,subnet_name,address_range,subnets):
#         """
#         This figures out whether we should be putting a name or an address into the rule
#         If it is a name, it must be a subnet name from within the tenancy
#         Otherwise we return the ip address with a subnet mask in the CIDR format
#         :param subnet_name: Contains the name of an address
#         :param address_range: Contains a CIDR address
#         :param subnets: Is the pointer to the list of subnets in the Tenancy
#         :return:
#         """
#         # if we have name or address which do we use?
#         # if re.search("^oragit",subnet_name):
#         # new version looks up the names as the hash (should fail everytime)
#         if hash(subnet_name) in subnets and subnets[hash(address_range)].getCidr() == address_range:
#             self.logger.debug("Returned {} which has ip {}".format(subnet_name,address_range))
#             return "${var.{}}".format(self.__convertTocidr(subnet_name))
#         else:
#             self.logger.debug("Unable to find CIDR {} for {}, determining if address has proper format".format(address_range, subnet_name))
#             return address_range
#             #We should assume that the address is already valid when the file is read                                                                                                subnet_name))
#             #addressreturn = address_range.strip()
#             # see if it ends in /XX
#             #m = re.search(r'([\d.]+)\/(\d\d?)',addressreturn)
#             #if m:
#             #    self.logger.debug("Looking at address {} with subnet length {}".format(m.group(1), m.group(2)))
#             #    # if yes is the value between 0 and 32 inclusive
#             #    if int(m.group(2)) > -1 or int(m.group(2)) < 33:
#             #        self.logger.debug("Returning IP {} from subnet {}".format(addressreturn, subnet_name))
#             #        return addressreturn
#             # else make it /32 as a safety precaution
#             #m = re.search(r'^([\d.]+)',addressreturn)
#             #if m:
#             #    self.logger.warning("Returning IP {} which has no mask, setting to /32 from subnet {}".format(address_range,
#             #                                                                                                  subnet_name))
#             #    return m.group(1)+'/32'
#             #else:
#             #    self.logger.debug("Could not determine the IP, subnet_name = {}; address_range = {}".format(subnet_name,addressreturn))
#             #    return None

#     # figure out whether a range, a single port, or all ports
#     #def __returnPorts(self,portString, portString2):
#     #    # so no parsing of the actual values here
#     #    portString = str(portString).strip()
#     #    portString2 = str(portString2).strip()
#     #    self.logger.debug("Request for ports given portString {}, portString2 {}".format(portString, portString2))
#     #    if portString == 'all' or portString2 == 'all' or (portString == '1' and portString2 == '65535'):
#     #        self.logger.debug("Detecting an all statement using portString {}, portString2 {}".format(portString,
#     #                                                                                                  portString2))
#     #        return 'all','all'
#     #    # TODO check the values are not over 65535
#     #    # TODO check that portString is less than or equal to portString2
#     #    elif re.search(r"^\d{1,5}$", portString) and re.search(r"^\d{1,5}$", portString2): return portString,portString2
#     #    elif portString == '-' and re.search(r"^\d{1,5}$", portString2): return portString2,portString2
#     #    elif portString2 == '-' and re.search(r"^\d{1,5}$", portString): return portString, portString
#     #    else:
#     #        self.logger.debug("Invalid port value {}-{}".format(portString, portString2))
#     #        raise ValueError("Invalid port value {}-{}".format(portString, portString2))

#     #def __returnProtocol(self,protString):
#     #    if re.search('all',protString,re.I): return 'all'
#     #    elif re.search(r'udp/?\w*',protString,re.I): return 'udp'
#     #    elif re.search(r'tcp/?\w*',protString,re.I): return 'tcp'
#     #    elif re.search(r'icmp/?\w*',protString,re.I): return 'icmp'
#     #    else: raise ValueError("Invalid protocol value {}".format(protString))

#     # takes a dictionary for subnets and adds rules toactually
#     # TODO we also need the ability to detect protocols of TCP; UDP and separate them out to two lines
#     def addToConfig(self, subnets, seclists):
#         """
#         This will return
#         :param subnets: a dictionary filled with the Subnet objects
#         :param seclists: a dictionary filled with SecList objects
#         :return: nothing
#         """
#         #if not isinstance(subnets, dict):
#         #    raise ValueError("{0} is not a valid".format(subnets))
#         #if not isinstance(seclists, dict):
#         #    raise ValueError("{0} is not a valid".format(seclists))

#         for index, row in enumerate(self.getSeclistsFromCSV()):
#             self.logger.debug("{} {}".format(index+2, row))
#             # setup the cells
#             """
#             Validate that the protocol is valide otherwise we'll skip this row
#             """
#             ### Already validated!
#             #try:
#             #    protocol = self.__returnProtocol(row[self.columns['SECPROTOCOL']])
#             #except ValueError as e:
#             #    self.logger.error("Found invalid protocol definition {}, in Workbook {}. Skipping row {}.".format(
#             #        row[self.columns['SECPROTOCOL']], self.fileName, index+3))
#             #    continue
#             #parse the ports file
#             #"""
#             #Validate that the the ports are valid otherwise we skip this row
#             #"""
#             # Already validated
#             # TODO we currently presume that ICMP will always be all ports (which is code and message
#             #try:
#             #    minPort, maxPort = self.__returnPorts(row[const.MIN], row[const.MAX])
#             #except ValueError as e:
#             #    if row[self.columns['SECPROTOCOL']] is not "icmp":
#             #        self.logger.error("Found invalid port range {}-{}, in Workbook {} for protocol {}. Skipping row {} ".format(
#             #            row[const.MIN], row[const.MAX], self.fileName, row[self.columns['SECPROTOCOL']], index+3))
#             #    else:
#             #        self.logger.debug("Found invalid port range {}-{}, in Workbook {} for protocol {}. Skipping row {} ".format(
#             #            row[const.MIN], row[const.MAX], self.fileName, prorow[self.columns['SECPROTOCOL']]tocol, index+3))
#             #    continue
#             """
#             Now the meat of the module, we will decide if a rule is ingress or egress
#             If it is a general and handle that specially
#             Note that just because a rule hits egress, doesn't mean it might also be an ingress too as well as several
#             networks
#             """
#             try:
#                 # EGRESS
#                 address = self.__nameOrAddress(row['SECDSTNAME'],row['SECDSTADDR'],subnets)
#                 self.logger.debug("Egress rule check. {} being used as address for seclist on row with data {}".format(
#                     address, row))
#                 # if the source address is a general address
#                 if self.__isGeneralSecList(row['SECSRCADDR']):
#                     self.logger.debug("Egress rule be in added to general seclist. {}".format(row['SECSRCADDR']))
#                     # add egress general rule
#                     self.__generalSecList(True,row['SECSRCNAME'],row['SECSRCADDR'],row['SECDSTNAME'],row['SECDSTADDR'],
#                                           row['SECPROTOCOL'], row['SECMINPORT'], row['SECMAXPORT'], seclists, subnets)
#                 # Otherwise lets see if we can match the source name in the list of subnets (DEPRECATED)
#                 elif hash(row['SECSRCADDR']) in subnets:
#                     self.logger.debug("Egress rule for subnet {}, to {} on port {}".format(
#                         subnets[hash(row['SECSRCADDR'])].getName(), address, str(row['SECMINPORT'])+":"+str(row['SECMAXPORT'])))
#                     addresult = subnets[hash(row[self.columns['SECSRCADDR']])].addSecListLine(1, address, minPort, maxPort, row[self.columns['SECPROTOCOL']],True)
#                 elif ipaddress.ip_network(row['SECSRCADDR']).overlaps(ipaddress.ip_network('10.15.0.0/16')):
#                     """ If the ip address is inside the tenancy it means this must be some kind of summarised address
#                     so therefore we need to discover what it contains, this is cpu intensive
#                     """
#                     for subnet in subnets:
#                         if subnets[subnet].is_inside(row['SECSRCADDR']):
#                             self.logger.debug("Egress rule for subnet {}, to {} on port {}".format(
#                                 subnets[subnet].getName(), address, str(row['SECMINPORT']) + ":" + str(row['SECMAXPORT'])))
#                             subnets[subnet].addSecListLine(1, address, row['SECMINPORT'], row['SECMAXPORT'], row['SECPROTOCOL'], True)
#                 elif re.search(r'^10\.15\.', str(row['SECSRCADDR'])):
#                     if hash(row['SECSRCADDR']) in subnets:
#                         self.logger.debug("Egress rule for subnet {}, to {} on port {}".format(
#                             subnets[hash(str(row['SECSRCADDR']))].getName(), address,
#                             str(row['SECMINPORT']) + ":" + str(row['SECMAXPORT'])))
#                         addresult = subnets[hash(row['SECSRCADDR'])].addSecListLine(1, address, row['SECMINPORT'], row['SECMAXPORT'],
#                                                                                     row['SECPROTOCOL'], True)
#                     else:
#                         self.logger.info(
#                             "Undeployed network {} in port matrix with Security Rule {}. Possible summarisation".format(
#                                 row[0], (address, row['SECMINPORT'], row['SECMAXPORT'], row['SECPROTOCOL'])))

#                 # INGRESS
#                 address = self.__nameOrAddress(row['SECSRCNAME'],row['SECSRCADDR'],subnets)
#                 self.logger.debug("Ingress rule check. {} being used as address for seclist on row with data {}".format(address, row))
#                 self.logger.debug("Details for summarised destination subnets ADD {}, NAM {}".format(row['SECDSTADDR'],row['SECDSTNAME']))
#                 # if the destinations address is a general address
#                 if self.__isGeneralSecList(row['SECDSTADDR']):
#                     self.logger.debug("Ingress rule be added to general seclist. {}".format(row['SECDSTADDR']))
#                     #add ingress general rule
#                     self.__generalSecList(False,row['SECSRCNAME'],row['SECSRCADDR'],row['SECDSTNAME'],row['SECDSTADDR'],row['SECPROTOCOL'],row['SECMINPORT'], row['SECMAXPORT'],seclists, subnets)
#                 # Otherwise lets see if we can match the source name in the list of subnets (DEPRECATED)
#                 elif hash(row['SECDSTADDR']) in subnets:
#                     addresult = subnets[hash(row['SECDSTADDR'])].addSecListLine(0, address, row['SECMINPORT'], row['SECMAXPORT'], row['SECPROTOCOL'], True)
#                     self.logger.debug("Ingress rule for subnet {}, to {} on port {}".format(subnets[hash(row['SECDSTADDR'])].getName(),address,str(row['SECMINPORT'])+":"+str(row['SECMAXPORT'])))
#                 # see if we can find the destination address in the subnet list, because ingress side is added to the destination net
#                 elif ipaddress.ip_network(row['SECDSTADDR']).overlaps(ipaddress.ip_network('10.15.0.0/16')):
#                     """ If the ip address is inside the tenancy it means this must be some kind of summarised address
#                     so therefore we need to discover what it contains, this is cpu intensive
#                     """
#                     for subnet in subnets:
#                         if subnets[subnet].is_inside(row['SECDSTADDR']):
#                             self.logger.debug("Ingress rule for subnet {}, to {} on port {}".format(
#                                 subnets[subnet].getName(), address, str(row['SECMINPORT']) + ":" + str(row['SECMAXPORT'])))
#                             subnets[subnet].addSecListLine(1, address, row['SECMINPORT'], row['SECMAXPORT'], row['SECPROTOCOL'], True)
#                 elif re.search(r'^10\.15\.', str(row['SECDSTADDR'])):
#                     if hash(row['SECDSTADDR']) in subnets:
#                         addresult = subnets[hash(row['SECDSTADDR'])].addSecListLine(0, address, row['SECMINPORT'], row['SECMAXPORT'], row['SECPROTOCOL'], True)
#                         self.logger.debug("Ingress rule for subnet {}, to {} on port {}".format(
#                             subnets[hash(row['SECDSTADDR'])].getName(), address, str(row['SECMINPORT']) + ":" + str(row['SECMAXPORT'])))
#                     else:
#                         self.logger.info(
#                             "Undeployed network {} in port matrix with Security Rule {}. Possible summarisation".format(
#                                 row[0], (address, row['SECMINPORT'], row['SECMAXPORT'], row['SECPROTOCOL'])))

#             except KeyError as e:
#                 # print "Incorrect subnet hash with data {}".format(row)
#                 self.logger.critical("Incorrect subnet hash with data {} with error {}".format(e,sys.exc_info()[-1].tb_lineno))
#                 self.logger.critical(traceback.print_exc(limit=None, file=sys.stdout))
#                 exit(-1)
#             except ValueError as e:
#                 self.logger.critical("Incorrect subnet data {} with error {}".format(e,sys.exc_info()[-1].tb_lineno))

#             self.logger.debug("End of line {}".format(index+2))


#             # else we skip because no rule needs to be implemented for this set of rules. implicit

#     #def getAllRows(self):
#     #    alist = list()
#     #    for index, row in enumerate(self.PMSheet.iter_rows()):
#     #        if index > self.startRow:
#     #            # this row does a validate perhaps create a separate subroutine for this
#     #            if not( row[0].internal_value == None or row[1].internal_value == None or row[2].internal_value == None or row[3].internal_value == None or row[4].internal_value == None or row[5].internal_value == None):
#     #                sourcename = row[0].internal_value.encode('ascii', errors='ignore').split('\n')
#     #                sourceaddress = row[1].internal_value.encode('ascii', errors='ignore').split('\n')
#     #                destinationname = row[2].internal_value.encode('ascii', errors='ignore').split('\n')
#     #                destinationaddress = row[3].internal_value.encode('ascii', errors='ignore').split('\n')
#     #                # need to cover index errors here
#     #                try:
#     #                    for i in range(0, len(sourcename)):
#     #                        for j in range(0, len(destinationname)):
#     #                            line = (sourcename[i],sourceaddress[i],destinationname[j],destinationaddress[j],row[4].internal_value.strip(),str(row[5].internal_value).strip())
#     #                            alist.append(line)
#     #                except IndexError as e:
#     #                    logger.error("Unequal contents at line {}: {} i{},{} j{}".format(index+1, sourcename, i, destinationname, j))
#     #                    exit(-1)
#     #    return alist

#     def isValidSubnetName(self, name):
#         #TODO
#         return True

#     def getCleanRange(self, range):
#         if range.strip().lower() == 'any':
#             return '0.0.0.0/0'
#         try:
#             if isinstance(ipaddress.ip_address(range),ipaddress.IPv4Address):
#                 return range + '/32'
#         except Exception as e:
#             self.logger.debug(e)

#         return range.strip()

#     def isValidCIDRBlock(self, range):
#         try:
#             if isinstance(ipaddress.ip_network(range), ipaddress.IPv4Network):
#                 return True
#         except Exception as e:
#             self.logger.error(e)
#             return False
#         # this shouldn't be needed, but just to make sure
#         return False


#     def isValidPortRange(self, min_port, max_port):
#         try:
#             if 0 <= int(min_port) and int(min_port) <= int(max_port) and int(max_port) <= 65535:
#                 return True
#         except:
#             return False
#         return False

#     def getCleanProtocol(self,protocol):
#         for key in const.SECPROTOCOLMAP.keys():
#             if protocol in const.SECPROTOCOLMAP[key]:
#                 return key
#         else:
#             return protocol

#     def isValidProtocol(self, protocol):
#         if protocol.upper() in const.SECALLOWEDPROTO:
#             return True
#         else:
#             return False

#     def getSeclistsFromCSV(self):
#         alist = list()
#         reader = csv.reader(self.ws, delimiter=',')
#         index = 0
#         print ("Loading seclist rules")
#         for row in reader:
#             index = index + 1
#             if index < self.startRow:
#                 print ("_", end='')
#                 continue
#             #self.logger.debug("Retrieving row data {}".format(currentrow.strip()))
#             #row = currentrow.strip().split(',')
#             self.logger.debug("Retrieving row split data {}".format(row))

#             src_range = self.getCleanRange(row[self.columns['SECSRCADDR']])
#             dst_range = self.getCleanRange(row[self.columns['SECDSTADDR']])
#             protocol = self.getCleanProtocol(row[self.columns['SECPROTOCOL']])
#             # this row does a validate perhaps create a separate subroutine for this
#             if not self.isValidSubnetName(row[self.columns['SECSRCNAME']]):
#                 self.logger.error("Invalid SECSRCNAME '{}' in row {}".format(row[self.columns['SECSRCNAME']], index))
#                 print ("_", end='')
#                 continue
#             elif not self.isValidCIDRBlock(src_range):
#                 self.logger.error("Invalid SECSRCADDR '{}' in row {}".format(row[self.columns['SECSRCADDR']], index))
#                 print ("_", end='')
#                 continue
#             elif not self.isValidSubnetName(row[self.columns['SECDSTNAME']]):
#                 self.logger.error("Invalid SECDSTNAME '{}' in row {}".format(row[self.columns['SECDSTNAME']], index))
#                 print ("_", end='')
#                 continue
#             elif not self.isValidCIDRBlock(dst_range):
#                 self.logger.error("Invalid SECDSTADDR '{}' in row {}".format(row[self.columns['SECDSTADDR']], index))
#                 print ("_", end='')
#                 continue
#             elif not self.isValidPortRange(row[self.columns['SECMINPORT']],row[self.columns['SECMAXPORT']]):
#                 self.logger.error("Invalid SECMINPORT or SECMAXPORT '{}-{}' in row {}".format(row[self.columns['SECMINPORT']], row[self.columns['SECMAXPORT']], index))
#                 print ("_", end='')
#                 continue
#             elif not self.isValidProtocol(protocol):
#                 self.logger.error("Invalid SECPROTOCOL '{}' in row {}".format(row[self.columns['SECPROTOCOL']], index))
#                 print ("_", end='')
#                 continue
#             else:
#                 seclist_dict = dict()
#                 seclist_dict['SECSRCNAME'] = row[self.columns['SECSRCNAME']]
#                 seclist_dict['SECSRCADDR'] = src_range
#                 seclist_dict['SECDSTNAME'] = row[self.columns['SECDSTNAME']]
#                 seclist_dict['SECDSTADDR'] = dst_range
#                 seclist_dict['SECMINPORT'] = row[self.columns['SECMINPORT']]
#                 seclist_dict['SECMAXPORT'] = row[self.columns['SECMAXPORT']]
#                 seclist_dict['SECPROTOCOL'] = protocol
#                 self.logger.debug("Appending seclist line {} {}".format(index,seclist_dict))
#                 alist.append(seclist_dict)
#                 print ("#", end='')
#         print ("\nLoaded {} seclist rules out of {} lines".format(len(alist),index))
#         return alist

#     #def getSubnetsFromCSV(self):
#     #    alist = list()
#     # #   # iterate through all the rows
#     #    for index, row in enumerate(self.SNSheet.iter_rows()):
#     #        # format is name, ad number, vcn, region, compartment, tenancy,
#     #        # def __init__(self, Name, DisplayName,Region,CIDR,Compartment,VCN)
#     #        if not( row[0].internal_value is None or row[1].internal_value is None or row[2].internal_value is None or row[3].internal_value is None or row[4].internal_value is None or row[5].internal_value is None):
#     #            addresses = str(row[1].internal_value).split('\n') + str(row[3].internal_value).split('\n')
#     #            for line in addresses:
#     #                if not ipFormatCheck(line.strip()):
#     #                    raise ValueError("Invalid IP address on line "+str(index+1)+" "+line+str(row))
#     #            if not self.__isPortRange(row[5].internal_value):
#     #                raise ValueError("Invalid port range on line "+str(index+1))
#     #            alist.append(row)
#     #        elif index > self.startRow and not (row[0].internal_value is None or row[1].internal_value is None or row[2].internal_value is None or row[3].internal_value is None or row[4].internal_value is None or row[5].internal_value is None):
#     #                raise ValueError("Invalid data on row "+str(index+1))
#     #    return alist


#     #def getNextRow(self):
#     #    alist = list()
#     #    self.currentRow = self.currentRow + 1
#     #    for i in 'abcdef':
#     #        cell = i+int(self.currentRow)
#     #        alist.append = self.PMSheet[cell].internal_value
#     #    return alist

#     #def getCell(self, cell):
#     #    if re.search(r'\w+\d+'): return self.PMSheet[cell]
#     #    else: return None

#     #def getChanges(self):
#     #    returnstring = list()
#     #    version = self.getVersion()
#     #    for index, row in enumerate(self.PMSheet.iter_rows()):
#     #        if re.search(str(version),str(row[7].internal_value)):
#     #            # print index+1,
#     #            # for i in range(0,5):
#     #            #    print str(row[i].internal_value).split(),
#     #            #print
#     #            templist = list()
#     #            templist.append(index+1)
#     #            for i in range(0,5):
#     #                templist.append(str(row[i].internal_value).split())
#     #            returnstring.append(templist)
#     #    return returnstring

#     def getVersion(self):
#         return self.PMSheet['E5'].internal_value


# END OF PortMatrix
# detects an oragitnet address
# def isORAGITnet(string):
#     string = string.strip()
#     if re.search('^oragit-(ash|phx)1-net-vcn1-ad[1-3]-prod-ngcc-*$',string):
#         return True
#     return False

# net to sec value
# def convertTosec(string):
#     match = re.match(r'^(oragit-)(ash|phx)(\d-)net-(vcn1-)ad[1-3]-(.*)$',string)
#     return match.group(1)+match.group(2)+match.group(3)+"sec-"+match.group(4)+match.group(5)

# converts all adX addresses to AD1
# def mashSubnetName(subnetName):
#     matches = re.search(r'^(oragit-)(ash|phx)(\d-net-vcn1-ad)[1-3](.*)$', subnetName)
#     if matches:
#         return matches.group(1)+matches.group(2)+matches.group(3)+'1'+matches.group(4)
#     else:
#         return None

# from a net address, returns the region (phoenix or ashburn)
# def returnRegionFromName(subnetName):
#     matches = re.search(r'^oragit-(ash|phx)(\d+)-net-vcn1-ad[1-3].*$', subnetName)
#     if matches:
#         return matches.group(1)+matches.group(2)
#     else:
#         return None

# getting a multiline value and responding (this is due to excel spreadsheet cells with multiline addresses and networks)
# def returnAddressesFromString(subnetString):
#     return subnetString.split('\n')


# def ipFormatCheck(ip_str):
#    pattern = r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
#    if re.match(pattern, ip_str):
#       return True
#    else:
#       return False

# def setLogging(logfilename, loglevel):
#     """Module setting logging system. We're mixed mode at the moment.
#     This is trying to work as a module logger and also for the library section
#     Logging may not quite work as expected"""
#     if os.path.exists(logfilename):
#             os.remove(logfilename)
#     #default: critical only
#     # -v = error
#     # -vv = warning
#     # -vvv = info
#     # -vvvv = debug

#     if loglevel >= 4:
#         log = logging.DEBUG
#     elif loglevel ==3:
#         log = logging.INFO
#     elif loglevel == 2:
#         log = logging.WARNING
#     elif loglevel == 1:
#         log = logging.ERROR
#     elif loglevel < 1:
#         log = logging.CRITICAL

#     a_logger = logging.getLogger(__name__)
#     fh = logging.FileHandler(logfilename)
#     formatter = logging.Formatter('%(asctime)s: %(levelname)s : %(name)s : %(funcName)s %(message)s')
#     fh.setFormatter(formatter)
#     alogger.addHandler(fh)
#     alogger.setLevel(log)
#     alogger.log(60,'test Started Logging at level {}'.format(log))
#     return alogger

def outputSubnets(subnets, output_to_file=False, output_folder_base_string=''):
    if output_to_file and output_folder_base_string == '':
        log_text = "Output Folder not set! Disabling output to folder"
        logger.warning(log_text)
        print(log_text)
        output_to_file = False

    log_text = "Initiated subnet generation"
    logger.info(log_text)
    print(log_text)

    output_folder_base = Path(output_folder_base_string)
    if not output_folder_base.exists():
        output_folder_base.mkdir()

    subnets_count = len(subnets.keys())
    current_subnet = 0
    for key in subnets:
        if subnets[key]._artificial:
            subnets_count = subnets_count - 1

    for key in subnets:

        if isinstance(subnets[key], Subnet):
            if subnets[key]._artificial:
                # SKIP all artificial entries
                continue
            current_subnet = current_subnet + 1
            subnet_name = subnets[key].getName()
            subnet_region = subnets[key].getRegion()
            subnet_vcn = subnets[key].getVCN()
            ingress, egress = subnets[key].rulesUsed()
            log_text = "Generating subnet {}/{} .. {:.2%} - {} [{} Rules:i={}, e={}]".format(current_subnet,
                                                                                             subnets_count,
                                                                                             current_subnet / subnets_count,
                                                                                             subnet_name,
                                                                                             ingress + egress, ingress,
                                                                                             egress)
            logger.info(log_text)
            print(log_text)
            logger.debug(
                "Retrieved key {} for subnet {}, cidr {}".format(key, subnet_name, hash(subnets[key].getCidr())))

            if ingress + egress > float(config['SECLISTS']['WarningLevel']) * (int(config['SECLISTS']['MaxRules']) * (
                    int(config['SECLISTS']['AppSecLists']) + int(config['SECLISTS']['AppSecLists']))):
                logger.warning(
                    "Generating subnet {}/{} .. {:.2%} - {} [{} Rules:i={}, e={}]".format(current_subnet, subnets_count,
                                                                                          current_subnet / subnets_count,
                                                                                          subnet_name, ingress + egress,
                                                                                          ingress, egress))
            logger.debug("Writing: {}".format(subnet_name))
            if output_to_file:
                # TODO Remove this when the gitlab projects are renamed in region-vcn format
                if subnet_vcn == "vcn1":
                    if subnet_region in ['ash1', 'phx1', 'fra1', 'lhr1']:
                        subnet_vcn = ""
                if subnet_vcn == "":
                    output_folder = output_folder_base / subnet_region
                else:
                    print (subnet_name)
                    print (output_folder_base)
                    print (subnet_region)
                    print (subnet_vcn)

                    output_folder = output_folder_base / (subnet_region + "-" + subnet_vcn)
                if not output_folder.exists():
                    output_folder.mkdir()
                # should we remove old files from each folder?
                ofile = open(output_folder / (subnet_name + ".tf"), 'w')
                ofile.write(subnets[key].outputSubnetFile() + "\n")
                ofile.close()
            else:
                print (subnets[key].outputSubnetFile())
                print ("======= End of {0} =======\n".format(subnets[key].getName()))

    log_text = "Subnet generation completed"
    logger.info(log_text)
    print(log_text)


def outputSeclists(seclists, output_to_file=False, output_folder_base_string=''):
    # now we go through the list and produce some output
    if output_to_file and output_folder_base_string == '':
        log_text = "Output Folder not set! Disabling output to folder"
        logger.warning(log_text)
        print(log_text)
        output_to_file = False
    output_folder_base = Path(output_folder_base_string)
    log_text = "Initiate seclist generation"
    logger.info(log_text)
    print(log_text)

    seclists_count = len(seclists.keys())
    current_seclist = 0
    for key in seclists:
        current_seclist = current_seclist + 1
        logger.info("*Start of {0}".format(seclists[key].getName()))
        if args.output or args.prints:

            # print ("*Start of {0}".format(seclists[key].getName()))
            seclist_name = seclists[key].getName()
            seclist_region = seclists[key].getRegion()
            seclist_vcn = seclists[key].getVCN()
            ingress = seclists[key].numOfIngress()
            egress = seclists[key].numOfEgress()
            print (
                "Generating seclist {}/{} .. {:.2%} - {} [{} Rules:i={}, e={}]".format(current_seclist, seclists_count,
                                                                                       current_seclist / seclists_count,
                                                                                       seclist_name, ingress + egress,
                                                                                       ingress, egress))
            if (ingress + egress) > float(config['SECLISTS']['WarningLevel']) * int(config['SECLISTS']['MaxRules']):
                logger.warning("Warning! Over {:.2%} for seclist {}/{} .. {:.2%} - {} [{} Rules:i={}, e={}]".format(
                    float(config['SECLISTS']['WarningLevel']), current_seclist, seclists_count,
                    current_seclist / seclists_count, seclist_name, ingress + egress, ingress, egress))
            if args.output:
                # we get three sized tuple with each of the seclists, which we now need to output into separate files
                for index, seclistoutput in enumerate(seclists[key].outputSecListOrdered()):
                    # TODO Remove this when the gitlab projects are renamed in region-vcn format
                    if seclist_vcn == "vcn1":
                        if seclist_region in ['ash1', 'phx1', 'fra1', 'lhr1']:
                            seclist_vcn = ""
                    logger.debug("Writing: {}-{}\n{}".format(seclist_name, index + 1, seclistoutput))
                    if seclist_vcn == "":
                        output_folder = output_folder_base / seclist_region
                    else:
                        output_folder = output_folder_base / (seclist_region + "-" + seclist_vcn)
                    if not output_folder.exists():
                        output_folder.mkdir()
                    ofile = open(output_folder / "{}-{}.tf".format(seclist_name, index + 1), 'w')
                    logger.debug("Writing to file {}-{}.tf".format(seclist_name, index + 1))
                    ofile.write("{}\n".format(seclistoutput))
                    logger.debug("Writing to file {}-{}.tf the contencts\n{}".format(seclist_name, index + 1,
                                                                                     seclistoutput))
                    ofile.close()

            if args.prints:
                print ("Printing: {}".format(seclist_name))
                print (seclists[key].outputSecListOrdered())
                print ("*End of {0}\n".format(seclist_name))

    log_text = "Seclist generation completed"
    logger.info(log_text)
    print(log_text)


# if __name__ != '__main__':
#     if loglevel > 4:
#         log = logging.DEBUG
#     elif loglevel == 4:
#         log = logging.INFO
#     elif loglevel == 3:
#         log = logging.WARNING
#     elif loglevel == 2:
#         log = logging.ERROR
#     elif loglevel == 1:
#         log = logging.CRITICAL
#     elif loglevel == 0:
#         log = 60

#     if os.path.exists(logfilename):
#         os.remove(logfilename)
#     module_logger = logging.getLogger(__name__)
#     module_logger.setLevel(log)
#     formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(name)s : %(funcName)s %(message)s')
#     fh = logging.FileHandler(logfilename)
#     fh.setFormatter(formatter)
#     module_logger.addHandler(fh)
#     module_logger.log(log,"Module logging started")

# if __name__ == '__main__':

# const.MAXRULE = 50
# const.STARTROW = 6


parser = argparse.ArgumentParser(description='Creates blank subnet and seclist files')
parser.add_argument("-s", help="CSV export from GCSDT: All Applications Audit Extract", type=str,
                    metavar="<seclist csv>", )
parser.add_argument("-r", help="Switches on rules number listing", action="store_true", dest="rules", default=False)
parser.add_argument("-n", help="CSV export from GCSDT: All Subnets", metavar="<Subnet List csv>")
parser.add_argument("-o", help="Outputs files, otherwise just processes the spreadsheet", action="store_true",
                    dest="output", default=False)
parser.add_argument("-p", help="Prints contents to terminal", action="store_true", dest="prints", default=False)
parser.add_argument("-V", help="Prints out versioning information", action='store_true', dest="version", default=False)
parser.add_argument("-v", help="Set debugging level", action='count', default=2)
parser.add_argument("-f", help="Set output folder - defaults to YYYY-MM-DD", type=str,
                    default=time.strftime('%Y-%m-%d'))
args = parser.parse_args()

### Load Config
config = configparser.ConfigParser()
config.read('config/bfs.cfg')

# Set logging
log_file_name = 'Build_From_Scratch_v{}.{}.log'.format(majorVersion, minorVersion)
# log_file_name = 'bfs.log'
logger = logging.getLogger(config['LOGGING']['LoggerName'])

level = logging.CRITICAL  # Default = 0 -> critical[50] - stops program execution
if args.v == 1:
    level = logging.ERROR  # -v = 1 -> error[40] - outstanding issues that may need to be looked into
elif args.v == 2:
    level = logging.WARNING  # -vv = 2 -> warning[30] - situations where you would skip parsing a line, but the program continues
elif args.v == 3:
    level = logging.INFO  # -vvv = 3 -> info[20] - just information that shows normal advances through the script stages
elif args.v >= 4:
    level = logging.DEBUG  # -vvvv = 4 -> debug[10] - detailed information on how decisions are being made

fh = logging.FileHandler(log_file_name, mode='w')
fh.setFormatter(logging.Formatter('%(asctime)s, %(levelname)s : %(filename)s - %(funcName)s: %(message)s'))

fh.setLevel(level)
logger.setLevel(level)
logger.addHandler(fh)

logger.info("Started main logging to {}".format(log_file_name))

# pm_list = list()
if args.version:
    log_text = "sec Build Version: {}.{}.{}".format(majorVersion, minorVersion, patchVersion)
    logger.info(log_text)
    print (log_text)
    # TODO why do we need this? Commented for now
    # index = 0
    # if args.s:
    #    for item in args.s:
    #        match = re.search("(.*):(.*)",item[0])
    #        portmatrix_file = match.group(1)
    #        portmatrixsheet = match.group(2)
    #        pm_list.append(PortMatrix( portmatrix_file, const.STARTROW, portmatrixsheet))
    #        logger.info("Port Matrix {} Version: {}".format(portmatrix_file, pm_list[index].getVersion()))
    #        print ("Port Matrix {} Version: {}".format(portmatrix_file, pm_list[index].getVersion()))
    #        index = index + 1
    # exit(0)
elif args.s:
    # we need to have a network file at this point so fail if not there
    if not os.path.exists(args.s):
        log_text = "Seclist file not found: {}".format(args.n)
        logger.critical(log_text)
        print(log_text)
        exit(-1)
    if not args.n:
        log_text = "Missing subnet file in command: -s <subnet-file.csv>"
        logger.critical(log_text)
        print(log_text)
        exit(-1)
    else:
        if not os.path.exists(args.n):
            log_text = "Subnet file not found: {}".format(args.n)
            logger.critical(log_text)
            print(log_text)
            exit(-1)

    # Load networks section, uses <file>:<sheet> This is no longer needed with the CSV version
    #  matchstr = re.search(r"^(.*):(.*)$",args.n)
    #  networkfile = matchstr.group(1)
    #  networksheet = matchstr.group(2)
    #  subnet_file = SubnetFile(networkfile, const.NETSTARTROW, networksheet)
    # This is where the subnet file is loaded in

    log_text = "Reading from subnet file: {}".format(args.n)
    logger.info(log_text)
    print(log_text)
    subnets = SubnetFile(args.n, config).getSubnetsFromCSV()

    # for item in args.s:
    # match = re.search("(.*)",item[0])
    log_text = "Reading from portmatrix (seclist rules) file: {}".format(args.s)
    logger.info(log_text)
    print(log_text)
    seclists = PortMatrix(args.s, config).getSeclistsFromCSV()

    # pm_list.append(portmatrix_file)

    # Add the special cases for each region
    # TODO - this needs an update!
    log_text = "Setting up general seclists"
    logger.info(log_text)
    print(log_text)

    # seclists[hash('oragit-phx1-sec-vnc1-prod-general')] = SecList('oragit-phx1-sec-vnc1-prod-general', 'oragit-phx1-sec-vnc1-prod-general', 'phx1', 2)
    # seclists[hash('oragit-ash1-sec-vnc1-prod-general')] = SecList('oragit-ash1-sec-vnc1-prod-general', 'oragit-ash1-sec-vnc1-prod-general', 'ash1', 2)
    # seclists[hash('oragit-fra1-sec-vcn1-prod-general')] = SecList('oragit-fra1-sec-vcn1-prod-general', 'oragit-fra1-sec-vcn1-prod-general', 'fra1', 2)
    # seclists[hash(const.SECLISTGENERALLHR)] = SecList(const.SECLISTGENERALLHR,const.SECLISTGENERALLHR, 'lhr1', 2)

    # collect all the known subnets in the tenancy

    # print(subnets)
    # exit()
    # seclist_rules = portmatrix_file.getSeclistsFromCSV()

    # subnet_file.addToList(subnets, seclists)

    # for spreadsheet in pm_list:
    #    logger.info("Adding port matrix {} to the pm_list".format(spreadsheet))
    #    spreadsheet.addToConfig(subnets, seclists)
    # logger.info("Add all port matrices ")

    worker = BuildFromScratch(subnets, seclists, config)

    subnets = worker.generateSubnets()
    seclists = worker.generateSeclists()

    outputSubnets(subnets, args.output, args.f.strip())
    outputSeclists(seclists, args.output, args.f.strip())

    artificial_subnets = 0
    for key in subnets:
        if subnets[key]._artificial:
            artificial_subnets = artificial_subnets + 1
    log_text = "Number of subnets found: {0} real + {1} artificial = {2} ".format(len(subnets) - artificial_subnets,
                                                                                  artificial_subnets, len(subnets))
    logger.info(log_text)
    print(log_text)

    log_text = "Number of seclists created: {0}".format(len(seclists))
    logger.info(log_text)
    print(log_text)

# TODO and now we need to mess around with file names and some bits of contents

logger.info('Stopped main logger')

