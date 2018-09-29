import re
import xlrd
import const
import openpyxl
import os
from string import Template


book = openpyxl.load_workbook('/Users/slahiri/NGCCUPM.xlsx')
sheet = book.get_sheet_by_name('DEV PM 4.10')
cells = sheet['A48:G48']
ingressrule = list()
egressrule = list()
returnStrings = list()
index = 0
egresslist = str()
ingresslist = str()
ingresscount = 0
egresscount = 0
###Iterating over the columns of the GCSDT spreadsheet obtaining all the elements to build seclist

for c1, c2, c3, c4, c5, c6, c7 in cells:
    SecListRuleTemplateICMP = """
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
    srcadd = c1.value
    egressseclistname = re.sub('-net', '-sec', srcadd)
    egresseclistnamelist = egressseclistname.split(" ")
    region = srcadd[7:11]

    srcaddlist = srcadd.split("\n")
    print srcaddlist
    lensrcadd = len(srcaddlist)
    print lensrcadd
    srcip = c2.value
    srciplist = srcip.split(" ")
    lensrcip = len(srciplist)
    print srciplist[0]


    dstadd = c3.value
    ingressseclistname = re.sub('-net', '-sec', dstadd)
    ingresseclistnamelist = ingressseclistname.split(" ")
    dstaddlist = dstadd.split("\n")
    lendstadd = len(dstaddlist)
    print lendstadd
    dstip = c4.value
    dstiplist = dstip.split(" ")
    lendstip = len(dstiplist)

    comment = c7.value
    prot = c5.value
    protlist = prot.split(" ")
    lenprotlist = len(protlist)
    port = c6.value
    strport = str(port)
    if re.search('-', strport):
        splitat = '-'
        portlow = str[:splitat]
        porthigh = str[splitat:]
    else:
        portlow = port
        porthigh = port
    if "all" in strport:
        portlow = 0
        porthigh = 65536

    if prot.lower() == "tcp":
        Proto = "${var.Protocol-TCP}"
    elif prot.lower() == "udp":
        Proto = "${var.Protocol-UDP}"
    elif prot == "icmp":
        Proto = "${var.Protocol-ICMP}"
    elif prot.lower() == "ssh":
        Proto = "${var.Protocol-SSH}"
    elif prot.lower() == "all":
        Proto = "all"

    SecListHeader = """
    resource "oci_core_security_list" "{}" {{
    compartment_id  =   "${{var.sandbox_compartment_git_networks_ocid}}"
    display_name    =   "{}"
    vcn_id          =   "${{oci_core_virtual_network.oragit-{}-vcn1.id}}"
    """
    n = len(dstaddlist)
    ingresslist = "{}\t{{\n\t{}_options\t{{\n\t\t\"max\"\t= \"{}\"\n\t\t\"min\"\t= \"{}\"\n\t\t}}\n\t\tstateless = \"{}\"\n\t\tprotocol = \"{}\"\n\t\t{} = \"{}\"\n\t}},\n".format(
        comment, prot, porthigh, portlow, "false", Proto, "source", srcaddlist[1])
    print(ingresslist)
