import re
import xlrd
import const
import openpyxl
import os
from string import Template
import hashlib

MAXCOUNT = 100


Seclistheader1 = """
resource                      "oci_core_security_list" "{}-1" {{
    compartment_id            = "${{var.prod_compartment_git_networks_ocid}}"
    display_name              = "{}-1"
    vcn_id                    = "${{oci_core_virtual_network.oragit-{}-vcn1.id}}"
    ingress_security_rules    = [
    ]
    egress_security_rules     = [
    ]
}}
"""
Seclistheader2 = """
resource                      "oci_core_security_list" "{}-2" {{
    compartment_id            = "${{var.prod_compartment_git_networks_ocid}}"
    display_name              = "{}-2"
    vcn_id                    = "${{oci_core_virtual_network.oragit-{}-vcn1.id}}"
    ingress_security_rules    = [
    ]
    egress_security_rules     = [
    ]
}}
"""
Seclistheader3 = """
resource                      "oci_core_security_list" "{}-3" {{
    compartment_id            = "${{var.prod_compartment_git_networks_ocid}}"
    display_name              = "{}-3"
    vcn_id                    = "${{oci_core_virtual_network.oragit-{}-vcn1.id}}"
    ingress_security_rules    = [
    ]
    egress_security_rules     = [
    ]
}}
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

book = openpyxl.load_workbook('/Users/slahiri/oraclebmc/CloudART/oraclecli/cli-testing/ociclioutput/NGCC-DEV/tfdeployment/NGCCDEV.xlsx')
sheet = book.get_sheet_by_name('NGCCDEV')
cells = sheet['A2:G13']
subnetdict = {}
index = 0

###Iterating over the columns of the GCSDT spreadsheet obtaining all the elements to build seclist
os.chdir('/Users/slahiri/NGCCDEVfiles')
cwd = os.getcwd()
print "1", cwd
for c1, c2, c3, c4, c5, c6, c7 in cells:

    srcadd = c1.value
    srcaddlist = srcadd.split("\n")
    print srcaddlist[0]
    lensrcadd = len(srcaddlist)
    srccidr = c2.value
    srccidrlist = srccidr.split("\n")
    lensrccidr = len(srcaddlist)
    print srccidrlist[0]

    regionname = c3.value
    regionnamelist = regionname.split("\n")
    region = c4.value
    compname = c5.value

    AD = str(c6.value)
    if AD == "a1":
        avdomain = "ad1"
    elif AD == 'a2':
        avdomain = "ad2"
    elif AD == 'a3':
        avdomain = "ad3"

    vcn = c7.value
    cidrname = re.sub('net', 'cidr', srcadd)
    seclistname = re.sub('net', 'sec', srcadd)
    if AD == "a1":
        seclistname1 = str(seclistname).replace('ad1-', '')
    elif AD == "a2":
        seclistname1 = str(seclistname).replace('ad2-', '')
    elif AD == "ad3":
        seclistname1 = str(seclistname).replace('ad3-', '')

    if compname.lower() == "git-ngcc":
        compartment = "prod_compartment_git_ngcc_ocid"
    elif compname.lower() == "git-rmss-services":
        compartment = "prod_compartment_git_rmss_services"
    elif compname.lower() == "git-network":
        compartment = "prod_compartment_git_network"
    elif compname.lower() == "git-rmss-tools-prod":
        compartment = "prod_compartment_git_rmss_tools_prod"
    elif compname.lower() == "git-rmss-mcafee-epo-dev":
        compartment = "prod_compartment_git_rmss_mcafee_epo_dev"
    elif compname.lower() == "git-rmss-mcafee-epo-prod":
        compartment = "prod_compartment_git_rmss_mcafee_epo_prod"
    elif compname.lower() == "git-rmss-mcafee-siem-dev":
        compartment = "prod_compartment_git_rmss_mcafee_siem_dev"
    elif compname.lower() == "git-rmss-mcafee-siem-prod":
        compartment = "prod_compartment_git_rmss_mcafee_siem_prod"
    elif compname.lower() == "git-devops":
        compartment = "prod_compartment_git_devops"
    elif compname.lower() == "git-sandbox":
        compartment = "git_sandbox"

    seclistheaderfin1 = Seclistheader1.format(seclistname1, seclistname1, region)
    seclistheaderfin2 = Seclistheader2.format(seclistname1, seclistname1, region)
    seclistheaderfin3 = Seclistheader3.format(seclistname1, seclistname1, region)

    os.chdir('/Users/slahiri/NGCCDEVfiles')
    cwd = os.getcwd()
    print "1", cwd

    with open('%s-1.tf' % (seclistname1), "w+") as secf:
        seclist1 = seclistheaderfin1
        secf.write(seclistheaderfin1)
        print("###############BLANK SECLIST {} IN REGION {} IS CREATED WHICH IS ASSOCIATED TO SUBNET {} AND IN VCN {} HAS BEEN CREATED".format(seclistname1, region, srcadd, vcn))
    with open('%s-2.tf' % (seclistname1), "w+") as secf:
        seclist2 = seclistheaderfin2
        secf.write(seclistheaderfin2)
        print("###############BLANK SECLIST {} IN REGION {} IS CREATED WHICH IS ASSOCIATED TO SUBNET {} AND IN VCN {} HAS BEEN CREATED".format(seclistname1, region, srcadd, vcn))

    with open('%s-3.tf' % (seclistname1), "w+") as secf:
        seclist3 = seclistheaderfin3
        secf.write(seclistheaderfin3)
        print("###############BLANK SECLIST {} IN REGION {} IS CREATED WHICH IS ASSOCIATED TO SUBNET {} AND IN VCN {} HAS BEEN CREATED".format(seclistname1, region, srcadd, vcn))


