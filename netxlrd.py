import re
import xlrd
import const
import openpyxl
import os
from string import Template

MAXCOUNT = 100

SecListHeader = """
resource "oci_core_security_list" "{}" {{
    compartment_id  =   "${{var.sandbox_compartment_git_networks_ocid}}"
    display_name    =   "{}"
    vcn_id          =   "${{oci_core_virtual_network.oragit-{}-vcn1.id}}"
"""

NetTemplate = """variable "{0}"	{{ default = "{1}" }}

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

SecListRuleTemplate = """
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

SecListRuleTemplateAll = """
{0}
    {{
    stateless = "{4}"
    protocol = "{5}"
    {6} = "{7}"
    }},
"""

icmptemplate = """
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
def __convertToSec(string):
    match = re.match('^(oragit-)(ash|phx)(\d-)net-(vcn\d-)ad[1-3]-(.*)$', string.strip())
    if match:
        return match.group(1) + match.group(2) + match.group(3) + "sec-" + match.group(4) + match.group(5)
    else:
        match = re.match('^(.*)-ad[1-3](.*)', string.strip())
        if match:
            return match.group(1) + match.group(2) + '-sec'
        return string.strip() + "-sec"

#if protocol == 'icmp' and lowPort != 'all':
#    returnstring = \
#        const.SecListRuleTemplateICMP.format(comment, lowPort, highPort, stateful,
#                                             direction, sourceAdd)

os.mkdir('/Users/slahiri/pyfiles')
book = openpyxl.load_workbook('/Users/slahiri/NGCCUPM.xlsx')
sheet = book.get_sheet_by_name('DEV PM 4.10')
cells = sheet['A48:G58']
ingressrule = list()
egressrule = list()
returnStrings = list()
index = 0
egresslist = str()
ingresslist = str()
egresslist2 = str()
ingresslist2 = str()
###Iterating over the columns of the GCSDT spreadsheet obtaining all the elements to build seclist
count = 1
cspread = 1
countingress = 0
countegress = 0
for c1, c2, c3, c4, c5, c6, c7 in cells:
    cspread = cspread + 1

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
    IngressSecListStarter = """
    ingress_security_rules    = [
    """
    IngressSecListEnd = """
    ]  
    """
    EgressSecListStarter = """
    egress_security_rules     = [
    """
    EgressSecListEnd = """
    ]
    """
    
    srcadd = c1.value

    egressseclistname = re.sub('-net', '-sec', srcadd)
    print egressseclistname
    egresseclistnamelist = egressseclistname.split("\n")
    print egresseclistnamelist[0]
#    print egresseclistnamelist[1]
    region = srcadd[7:11]

    srcaddlist = srcadd.split("\n")
    print srcaddlist[0]
#    print srcaddlist[1]
    lensrcadd = len(srcaddlist)
    srcip = c2.value
    srciplist = srcip.split("\n")
    lensrcip = len(srciplist)
    print srciplist[0]
#    print srciplist[1]

    dstadd = c3.value
    ingressseclistname = re.sub('-net', '-sec', dstadd)
    ingresseclistnamelist = ingressseclistname.split("\n")
    dstaddlist = dstadd.split("\n")
    n = len(dstaddlist)
    lendstadd = len(dstaddlist)
    print lendstadd
    dstip = c4.value
    dstiplist = dstip.split("\n")
    lendstip = len(dstiplist)

    comment = str(c7.value)
    prot = c5.value
    protlist = prot.split("\n")
    lenprotlist = len(protlist)
    port = c6.value
    strport = str(port)
    if re.search('-', strport):
        splitat = '-'
        portlow = strport[:splitat]
        porthigh = strport[splitat:]
    else:
        portlow = port
        porthigh = port
    if "all" in strport:
        portlow = 0
        porthigh = 65536

    if prot.lower() == "tcp":
        protfin = "tcp"
        Proto = "${var.Protocol-TCP}"
    elif prot.lower() == "udp":
        Proto = "${var.Protocol-UDP}"
        protfin = "udp"
    elif prot.lower() == "icmp":
        Proto = "${var.Protocol-ICMP}"
        protfin = "icmp"
    elif prot.lower() == "ssh":
        Proto = "${var.Protocol-SSH}"
        protfin = "tcp"
    elif prot.lower() == "http":
        Proto = "${var.Protocol-HTTP}"
        protfin = "tcp"
    elif prot.lower() == "https":
        Proto = "${var.Protocol-HTTPS}"
        protfin = "tcp"
    elif prot.lower() == "http/s":
        Proto = "${var.Protocol-HTTPS}"
        protfin = "tcp"
    elif prot.lower() == "sqlnet":
        Proto = "${var.Protocol-SQLNET}"
        protfin = "tcp"
    elif prot.lower() == "imap4":
        Proto = "${var.Protocol-IMAP4}"
        protfin = "tcp"
    elif prot.lower() == "smtp":
        Proto = "${var.Protocol-SMTP}"
        protfin = "tcp"
    elif prot.lower() == "all":
        Proto = "all"
        protfin = "all"

    n = len(dstaddlist)
    if prot.lower() == 'icmp' and portlow.lower() != 'all':
### TO ACCOUNT FOR 2 SUBNET ENTRIES PER ROW IN THE GCSDT SPREADSHEET
        if n == 2:
            ingresslist = icmptemplate.format("######" + comment, portlow, porthigh, "false", Proto, "source", srcaddlist[0])
            ingresslist2 = icmptemplate.format("#######" + comment, portlow, porthigh, "false", Proto, "source", srcaddlist[1])
            egresslist = icmptemplate.format("#######" + comment, portlow, porthigh, "false", Proto, "destination", dstaddlist[0])
            egresslist2 = icmptemplate.format("#######" + comment, portlow, porthigh, "false", Proto, "destination", dstaddlist[1])
            print(egresslist2)
            os.chdir('/Users/slahiri/pyfiles')
            cwd = os.getcwd()
            print "1", cwd
            with open('%s-%s.tf' % (egressseclistname, count), "a+") as egsec:
                contents = egsec.read()
                countdest = contents.count("destination")
                print("The number of egress rules is {} for 2 row entries spreadsheet".format(countdest))
                lines = egsec.readlines()
                if EgressSecListStarter in lines and EgressSecListEnd not in lines and countdest < 10:
                    egsec.writelines(egresslist)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))
                    egsec.writelines(egresslist2)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[1], dstaddlist[1], countdest + 1))
                elif EgressSecListStarter not in lines and countdest < 10:
                    egsec.writelines(SecListHeader.format(__convertToSec(srcaddlist[0]), __convertToSec(srcaddlist[0]),region) + EgressSecListStarter + egresslist)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))
                    egsec.writelines(egresslist2)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[1], dstaddlist[1], countdest + 1))

                #### cspread upper limit count is obtained by subtracting (line 101) cell range obtained from GCSDT spreadsheet = sheet['Ax:Gy']######
                elif countdest > 10 and countdest < MAXCOUNT:
                    egsec.writelines(egresslist)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcadd[0], dstadd[0], countdest + 1))
                    egsec.writelines(egresslist2 + EgressSecListEnd)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcadd[1], dstadd[1], countdest + 1))
                elif countdest > MAXCOUNT:
                    print("The current seclist {} has reached 100 RULES CAPACITY and hence we are creating the 2nd seclist".format(egressseclistname))
                    count = count + 1
                    with open('%s-%s.tf' % (egressseclistname, count), "a+") as egsec:
                        contents = egsec.read()
                        countdest = contents.count("destination")
                        lines = egsec.readlines()
                        if EgressSecListStarter in lines and EgressSecListEnd not in lines and countdest < 10:
                            egsec.writelines(egresslist)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))
                            egsec.writelines(egresslist2)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[1], dstaddlist[1], countdest + 1))
                        elif EgressSecListStarter not in lines and countdest < 10:
                            egsec.writelines(SecListHeader.format(__convertToSec(srcaddlist[0]), __convertToSec(srcaddlist[0]),region) + EgressSecListStarter + egresslist)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))
                            egsec.writelines(egresslist2)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[1], dstaddlist[1], countdest + 1))

                        elif countdest > 10:
                            egsec.writelines(egresslist)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcadd[0], dstadd[0], countdest + 1))
                            egsec.writelines(egresslist2 + EgressSecListEnd)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcadd[1], dstadd[1], countdest + 1))

            with open('%s-%s.tf' % (ingressseclistname, count), "a+") as insec:
                contents = insec.read()
                countsrc = contents.count("source")
                lines = egsec.readlines()
                print("The number of ingress rules is {} for 2 row entries spreadsheet".format(countsrc))
                if IngressSecListStarter in lines and IngressSecListEnd not in lines and countsrc < 10:
                    insec.writelines(ingresslist)
                    insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))
                    insec.writelines(ingresslist2)
                    insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[1], srcaddlist[1], countsrc + 1))
                elif IngressSecListStarter not in lines and countsrc < 10:
                    insec.writelines(SecListHeader.format(__convertToSec(dstaddlist[0]), __convertToSec(dstaddlist[0]),region) + IngressSecListStarter + ingresslist)
                    insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countdest + 1))
                    insec.writelines(ingresslist2)
                    insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[1], srcaddlist[1], countdest + 1))
                elif countsrc > 10 and countsrc < MAXCOUNT:
                    insec.writelines(ingresslist)
                    insec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))
                    insec.writelines(ingresslist2 + IngressSecListEnd)
                    insec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(dstaddlist[1], srcaddlist[1], countsrc + 1))
                elif countingress > MAXCOUNT:
                    print("The current seclist {} has reached 100 RULES CAPACITY and hence we are creating the 2nd seclist".format(ingressseclistname))
                    count = count + 1
                    with open('%s-%s.tf' % (ingressseclistname, count), "a+") as insec:
                        contents = insec.read()
                        countsrc = contents.count("source")
                        lines = egsec.readlines()
                        if IngressSecListStarter in lines and IngressSecListEnd not in lines and countsrc < 10:
                            insec.writelines(ingresslist)
                            insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))
                            insec.writelines(ingresslist2)
                            insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[1], srcaddlist[1], countsrc + 1))
                        elif IngressSecListStarter not in lines and countsrc < 10:
                            insec.writelines(SecListHeader.format(__convertToSec(dstaddlist[0]), __convertToSec(dstaddlist[0]),region) + IngressSecListStarter + ingresslist)
                            insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countdest + 1))
                            insec.writelines(ingresslist2)
                            insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[1], srcaddlist[1], countdest + 1))
                        elif countsrc > 10:
                            insec.writelines(ingresslist)
                            insec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))
                            insec.writelines(ingresslist2 + IngressSecListEnd)
                            insec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(dstaddlist[1], srcaddlist[1], countsrc + 1))

                print(os.system('ls -l'))


####TO ACCOUNT FOR 1 ROW ENTRY FOR SUBNET
        if n == 1:
            ingresslist = icmptemplate.format(comment, portlow, porthigh, "false", Proto, "source", srcaddlist[0])
            egresslist = icmptemplate.format(comment, portlow, porthigh, "false", Proto, "destination", dstaddlist[0])
            with open('%s-%s.tf' % (egressseclistname, n), "a+") as egsec:
                contents = egsec.read()
                countdest = contents.count("destination")
                print("The number of egress rules is {} for 1 row entry spreadsheet".format(countdest))
                ines = egsec.readlines()
                if EgressSecListStarter in lines and EgressSecListEnd not in lines and countdest < 10:
                    egsec.writelines(egresslist)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))
                    egsec.writelines(egresslist2)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[1], dstaddlist[1], countdest + 1))
                elif EgressSecListStarter not in lines and countdest < 10:
                    egsec.writelines(SecListHeader.format(__convertToSec(srcaddlist[0]), __convertToSec(srcaddlist[0]),region) + EgressSecListStarter + egresslist)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))
                    egsec.writelines(egresslist2)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[1], dstaddlist[1], countdest + 1))

                #### cspread upper limit count is obtained by subtracting (line 101) cell range obtained from GCSDT spreadsheet = sheet['Ax:Gy']######
                elif countdest > 10 and countdest < MAXCOUNT:
                    egsec.writelines(egresslist)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcadd[0], dstadd[0], countdest + 1))
                    egsec.writelines(egresslist2 + EgressSecListEnd)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcadd[1], dstadd[1], countdest + 1))
                elif countdest > MAXCOUNT:
                    print("The current seclist {} has reached 100 RULES CAPACITY and hence we are creating the 2nd seclist".format(egressseclistname))
                    count = count + 1
                    with open('%s-%s.tf' % (egressseclistname, count), "a+") as egsec:
                        contents = egsec.read()
                        countdest = contents.count("destination")
                        lines = egsec.readlines()
                        if EgressSecListStarter in lines and EgressSecListEnd not in lines and countdest < 10:
                            egsec.writelines(egresslist)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))
                            egsec.writelines(egresslist2)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[1], dstaddlist[1], countdest + 1))
                        elif EgressSecListStarter not in lines and countdest < 10:
                            egsec.writelines(SecListHeader.format(__convertToSec(srcaddlist[0]), __convertToSec(srcaddlist[0]),region) + EgressSecListStarter + egresslist)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))
                            egsec.writelines(egresslist2)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[1], dstaddlist[1], countdest + 1))

                        elif countdest > 10:
                            egsec.writelines(egresslist)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcadd[0], dstadd[0], countdest + 1))
                            egsec.writelines(egresslist2 + EgressSecListEnd)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcadd[1], dstadd[1], countdest + 1))
            with open('%s-%s.tf' % (ingressseclistname,count), "a+") as insec:
                contents = insec.read()
                countsrc = contents.count("source")
                print("The number of egress rules is {} for 1 row entry spreadsheet".format(countsrc))
                lines = egsec.readlines()
                if IngressSecListStarter in lines and IngressSecListEnd not in lines and countsrc < 10:
                    insec.writelines(ingresslist)
                    insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))

                elif IngressSecListStarter not in lines and countsrc < 10:
                    insec.writelines(SecListHeader.format(__convertToSec(dstaddlist[0]), __convertToSec(dstaddlist[0]),region) + IngressSecListStarter + ingresslist)
                    insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countdest + 1))

                elif countsrc > 10 and countsrc < MAXCOUNT:
                    insec.writelines(ingresslist)
                    insec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))

                elif countingress > MAXCOUNT:
                    print("The current seclist {} has reached 100 RULES CAPACITY and hence we are creating the 2nd seclist".format(ingressseclistname))
                    count = count + 1
                    with open('%s-%s.tf' % (ingressseclistname, count), "a+") as insec:
                        contents = insec.read()
                        countsrc = contents.count("source")
                        lines = egsec.readlines()
                        if IngressSecListStarter in lines and IngressSecListEnd not in lines and countsrc < 10:
                            insec.writelines(ingresslist)
                            insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))

                        elif IngressSecListStarter not in lines and countsrc < 10:
                            insec.writelines(SecListHeader.format(__convertToSec(dstaddlist[0]), __convertToSec(dstaddlist[0]),region) + IngressSecListStarter + ingresslist)
                            insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countdest + 1))

                        elif countsrc > 10:
                            insec.writelines(ingresslist)
                            insec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))

                print(os.system('ls -l'))

###CHECKING IF 
    elif prot.lower() != 'icmp':
        if n == 2:
            ingresslist = "{{\n\t{}_options\t{{\n\t\t\"max\"\t= \"{}\"\n\t\t\"min\"\t= \"{}\"\n\t\t}}\n\t\tstateless = \"{}\"\n\t\tprotocol = \"{}\"\n\t\t{} = \"{}\"\n\t}},\n".format(
                            protfin, porthigh, portlow, "false", Proto, "source", srcaddlist[0])
            print(IngressSecListStarter + ingresslist + IngressSecListEnd)
            egresslist = "{{\n\t{}_options\t{{\n\t\t\"max\"\t= \"{}\"\n\t\t\"min\"\t= \"{}\"\n\t\t}}\n\t\tstateless = \"{}\"\n\t\tprotocol = \"{}\"\n\t\t{} = \"{}\"\n\t}},\n".format(
                            protfin, porthigh, portlow, "false", Proto, "destination", dstaddlist[0])
            print(EgressSecListStarter + egresslist + EgressSecListEnd)
            ingresslist2 = "{{\n\t{}_options\t{{\n\t\t\"max\"\t= \"{}\"\n\t\t\"min\"\t= \"{}\"\n\t\t}}\n\t\tstateless = \"{}\"\n\t\tprotocol = \"{}\"\n\t\t{} = \"{}\"\n\t}},\n".format(
                            protfin, porthigh, portlow, "false", Proto, "source", srcaddlist[1])
            print(ingresslist2)
            egresslist2 = "{{\n\t{}_options\t{{\n\t\t\"max\"\t= \"{}\"\n\t\t\"min\"\t= \"{}\"\n\t\t}}\n\t\tstateless = \"{}\"\n\t\tprotocol = \"{}\"\n\t\t{} = \"{}\"\n\t}},\n".format(
                           protfin, porthigh, portlow, "false", Proto, "destination", dstaddlist[1])
            print(egresslist2)
            os.chdir('/Users/slahiri/pyfiles')
            cwd = os.getcwd()
            print "1", cwd
            with open('%s-%s.tf' % (egressseclistname,count), "a+") as egsec:
                contents = egsec.read().strip().split()
                print contents
                countdest = contents.count("destination")
                print("The number of egress rules is {} for 2 row entries spreadsheet".format(countdest))
                lines = egsec.readlines()
                print lines
                if "oci_core_security_list" in contents and  EgressSecListStarter in contents and EgressSecListEnd not in contents and countdest < 10:
                    egsec.writelines(egresslist)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))
                    egsec.writelines(egresslist2)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[1], dstaddlist[1], countdest + 1))
                elif "oci_core_security_list" not in contents and EgressSecListStarter not in contents and countdest < 10 :
                    egsec.writelines(SecListHeader.format(__convertToSec(srcaddlist[0]), __convertToSec(srcaddlist[0]), region) + EgressSecListStarter + egresslist)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))
                    egsec.writelines(egresslist2)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[1], dstaddlist[1], countdest + 1))

                elif "oci_core_security_list" in contents and EgressSecListStarter not in contents and countdest < 10 :
                    egsec.writelines(EgressSecListStarter + egresslist)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))
                    egsec.writelines(egresslist2)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[1], dstaddlist[1], countdest + 1))

#### cspread upper limit count is obtained by subtracting (line 101) cell range obtained from GCSDT spreadsheet = sheet['Ax:Gy']######
                elif countdest > 10 and countdest < MAXCOUNT:
                    egsec.writelines(egresslist)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcadd[0], dstadd[0], countdest + 1))
                    egsec.writelines(egresslist2 + EgressSecListEnd)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcadd[1], dstadd[1], countdest + 1))
                elif countdest > MAXCOUNT:
                    print("The current seclist {} has reached 100 RULES CAPACITY and hence we are creating the 2nd seclist".format(egressseclistname))
                    count = count + 1
                    with open('%s-%s.tf' % (egressseclistname, count), "a+") as egsec:
                        contents = egsec.read().strip().split()
                        countdest = contents.count("destination")
                        lines = egsec.readlines()
                        if "oci_core_security_list" in contents and EgressSecListStarter in contents and EgressSecListEnd not in contents and countdest < 10:
                            egsec.writelines(egresslist)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))
                            egsec.writelines(egresslist2)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[1], dstaddlist[1], countdest + 1))
                        elif "oci_core_security_list" not in contents and EgressSecListStarter not in contents and countdest < 10:
                            egsec.writelines(SecListHeader.format(__convertToSec(srcaddlist[0]), __convertToSec(srcaddlist[0]),region) + EgressSecListStarter + egresslist)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))
                            egsec.writelines(egresslist2)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[1], dstaddlist[1], countdest + 1))

                        elif "oci_core_security_list" in contents and EgressSecListStarter not in contents and countdest < 10:
                            egsec.writelines(EgressSecListStarter + egresslist)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))
                            egsec.writelines(egresslist2)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[1], dstaddlist[1], countdest + 1))
                        elif countdest > 10:
                            egsec.writelines(egresslist)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcadd[0], dstadd[0], countdest + 1))
                            egsec.writelines(egresslist2 + EgressSecListEnd)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcadd[1], dstadd[1], countdest + 1))

            with open('%s-%s.tf' % (ingressseclistname,count), "a+") as insec:
                contents = insec.read().strip().split()
                countsrc = contents.count("source")
                print("The number of egress rules is {} for 2 row entries spreadsheet".format(countsrc))
                lines = insec.readlines()
                if "oci_core_security_list" in contents and IngressSecListStarter in contents and IngressSecListEnd not in contents and countsrc < 10:
                    insec.writelines(ingresslist)
                    insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))
                    insec.writelines(ingresslist2)
                    insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[1], srcaddlist[1], countsrc + 1))
                elif "oci_core_security_list" not in contents and IngressSecListStarter not in contents and countsrc < 10:
                    insec.writelines(SecListHeader.format(__convertToSec(dstaddlist[0]), __convertToSec(dstaddlist[0]),region) + IngressSecListStarter + ingresslist)
                    insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countdest + 1))
                    insec.writelines(ingresslist2)
                    insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[1], srcaddlist[1], countdest + 1))
                elif "oci_core_security_list" in contents and IngressSecListStarter not in contents and countsrc < 10 :
                    insec.writelines(IngressSecListStarter + ingresslist)
                    insec.writelines("###############INGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countdest + 1))
                    insec.writelines(ingresslist2)
                    insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[1], srcaddlist[1], countdest + 1))
                elif countsrc > 10 and countsrc < MAXCOUNT:
                    insec.writelines(ingresslist)
                    insec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))
                    insec.writelines(ingresslist2 + IngressSecListEnd)
                    insec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(dstaddlist[1], srcaddlist[1], countsrc + 1))
                elif countsrc > MAXCOUNT:
                    print("The current seclist {} has reached 100 RULES CAPACITY and hence we are creating the 2nd seclist".format(ingressseclistname))
                    count = count + 1
                    with open('%s-%s.tf' % (ingressseclistname, count), "a+") as insec:
                        contents = insec.read().strip().split()
                        countsrc = contents.count("source")
                        lines = insec.readlines()
                        if "oci_core_security_list" in contents and IngressSecListStarter in contents and IngressSecListEnd not in contents and countsrc < 10:
                            insec.writelines(ingresslist)
                            insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))
                            insec.writelines(ingresslist2)
                            insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[1], srcaddlist[1], countsrc + 1))
                        elif "oci_core_security_list" not in contents and IngressSecListStarter not in contents and countsrc < 10:
                            insec.writelines(SecListHeader.format(__convertToSec(dstaddlist[0]), __convertToSec(dstaddlist[0]),region) + IngressSecListStarter + ingresslist)
                            insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))
                            insec.writelines(ingresslist2)
                            insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[1], srcaddlist[1], countsrc + 1))
                        elif "oci_core_security_list" in contents and IngressSecListStarter not in contents and countsrc < 10:
                            insec.writelines(IngressSecListStarter + ingresslist)
                            insec.writelines("###############INGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countdest + 1))
                            insec.writelines(ingresslist2)
                            insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[1], srcaddlist[1], countdest + 1))
                        elif countsrc > 10:
                            insec.writelines(ingresslist)
                            insec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))
                            insec.writelines(ingresslist2 + IngressSecListEnd)
                            insec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(dstaddlist[1], srcaddlist[1], countsrc + 1))

                print(os.system('ls -l'))

        if n == 1:
            ingresslist = "{{\n\t{}_options\t{{\n\t\t\"max\"\t= \"{}\"\n\t\t\"min\"\t= \"{}\"\n\t\t}}\n\t\tstateless = \"{}\"\n\t\tprotocol = \"{}\"\n\t\t{} = \"{}\"\n\t}},\n".format(
                           Proto, porthigh, portlow, "false", Proto, "source", srcaddlist[0])
            print(IngressSecListStarter + ingresslist + IngressSecListEnd)
            egresslist = "{{\n\t{}_options\t{{\n\t\t\"max\"\t= \"{}\"\n\t\t\"min\"\t= \"{}\"\n\t\t}}\n\t\tstateless = \"{}\"\n\t\tprotocol = \"{}\"\n\t\t{} = \"{}\"\n\t}},\n".format(
                          Proto, porthigh, portlow, "false", Proto, "destination", dstaddlist[0])
            print(EgressSecListStarter + egresslist + EgressSecListEnd)
            os.chdir('/Users/slahiri/pyfiles')
            cwd = os.getcwd()
            print "1", cwd
            with open('%s-%s.tf' % (egressseclistname, count), "a+") as egsec:
                contents = egsec.read().strip().split()
                countdest = contents.count("destination")
                print("The number of egress rules is {} for 1 row entry spreadsheet".format(countdest))
                lines = egsec.readlines()
                if "oci_core_security_list" in contents and EgressSecListStarter in contents and EgressSecListEnd not in contents and countdest < 10:
                    egsec.writelines(egresslist)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))

                elif "oci_core_security_list" not in contents and EgressSecListStarter not in contents and countdest < 10:
                    egsec.writelines(SecListHeader.format(__convertToSec(srcaddlist[0]), __convertToSec(srcaddlist[0]),region) + EgressSecListStarter + egresslist)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))


                elif "oci_core_security_list" in contents and EgressSecListStarter not in contents and countdest < 10:
                    egsec.writelines(EgressSecListStarter + egresslist)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))
                elif countdest > 10:
                    egsec.writelines(egresslist)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcadd[0], dstadd[0], countdest + 1))

                elif countdest > 10 and countdest < MAXCOUNT:
                    egsec.writelines(egresslist)
                    egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcadd[0], dstadd[0], countdest + 1))
                elif countdest > MAXCOUNT:
                    print("The current seclist {} has reached 100 RULES CAPACITY and hence we are creating the 2nd seclist".format(egressseclistname))
                    count = count + 1
                    with open('%s-%s.tf' % (egressseclistname, count), "a+") as egsec:
                        contents = egsec.read()
                        countdest = contents.count("destination")
                        if EgressSecListStarter in contents and EgressSecListEnd not in contents and countdest < 10:
                            egsec.writelines(egresslist)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))

                        elif EgressSecListStarter not in contents and countdest < 10:
                            egsec.writelines(SecListHeader.format(__convertToSec(srcaddlist[0]), __convertToSec(srcaddlist[0]),region) + EgressSecListStarter + egresslist)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcaddlist[0], dstaddlist[0], countdest + 1))

                        elif countdest > 10:
                            egsec.writelines(egresslist)
                            egsec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(srcadd[0], dstadd[0], countdest + 1))

            with open('%s-%s.tf' % (ingressseclistname, count), "a+") as insec:
                contents = insec.read()
                countsrc = contents.count("source")
                print("The number of egress rules is {} for 1 row entry spreadsheet".format(countsrc))
                lines = insec.readlines()
                if IngressSecListStarter in contents and IngressSecListEnd not in contents and countsrc < 10:
                    insec.writelines(ingresslist)
                    insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))
                elif IngressSecListStarter not in contents and countsrc < 10:
                    insec.writelines(SecListHeader.format(__convertToSec(dstaddlist[0]), __convertToSec(dstaddlist[0]),region) + IngressSecListStarter + ingresslist)
                    insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countdest + 1))
                elif "oci_core_security_list" in contents and IngressSecListStarter not in contents and countsrc < 10:
                    insec.writelines(IngressSecListStarter + ingresslist)
                    insec.writelines("###############INGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countdest + 1))
                elif countsrc > 10 and countsrc < MAXCOUNT:
                    insec.writelines(ingresslist)
                    insec.writelines("###############EGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))
                elif countingress > MAXCOUNT:
                     print("The current seclist {} has reached 100 RULES CAPACITY and hence we are creating the 2nd seclist".format(ingressseclistname))
                     count = count + 1
                     with open('%s-%s.tf' % (ingressseclistname, count), "a+") as insec:
                         contents = insec.read()
                         countsrc = contents.count("source")
                         lines = insec.readlines()
                         if IngressSecListStarter in contents and IngressSecListEnd not in contents and countsrc < 10:
                             insec.writelines(ingresslist)
                             insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countsrc + 1))
                         elif IngressSecListStarter not in contents and countsrc < 10:
                             insec.writelines(SecListHeader.format(__convertToSec(dstaddlist[0]), __convertToSec(dstaddlist[0]),region) + IngressSecListStarter + ingresslist)
                             insec.writelines("###############INGRESS SECLIST RULE FROM DESTINATION {} to SOURCE {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countdest + 1))
                         elif "oci_core_security_list" in contents and IngressSecListStarter not in contents and countsrc < 10:
                             insec.writelines(IngressSecListStarter + ingresslist)
                             insec.writelines("###############INGRESS SECLIST RULE FROM SOURCE {} to DESTINATION {} AND THIS IS THE {}th RULE".format(dstaddlist[0], srcaddlist[0], countdest + 1))
print(os.system('ls -l'))
