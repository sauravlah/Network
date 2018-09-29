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

NetTemplate = """variable "{}"	{{ default = "{}" }}

resource "oci_core_subnet" "{}" {{
    availability_domain       = "${{var.oragit-{}-ad{} }}"
    cidr_block                = "${{var.{} }}"
    compartment_id            = "${{var.{} }}"
    dhcp_options_id           = "${{oci_core_dhcp_options.oragit-{}-dhcp1.id}}"
    display_name              = "{}"
    vcn_id                    = "${{oci_core_virtual_network.oragit-{}-vcn1.id}}"
    route_table_id            = "${{oci_core_route_table.oragit-{}-rt1.id}}"
    security_list_ids         = [
                "${{oci_core_security_list.oragit-{}-sec-vcn1-prod-general-1.id}}",
                "${{oci_core_security_list.oragit-{}-sec-vcn1-prod-general-2.id}}",
                "${{oci_core_security_list.{}-1.id}}",
                "${{oci_core_security_list.{}-2.id}}",
                "${{oci_core_security_list.{}-3.id}}",
    ]
}}
"""

book = openpyxl.load_workbook('/Users/slahiri/oraclebmc/CloudART/oraclecli/cli-testing/ociclioutput/NGCC-DEV/tfdeployment/NGCCDEV.xlsx')
sheet = book.get_sheet_by_name('NGCCDEV')
cells = sheet['A2:G13']
subnetdict = {}
index = 0

###Iterating over the columns of the GCSDT spreadsheet obtaining all the elements to build seclist
os.mkdir('/Users/slahiri/NGCCDEVfiles')

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
        avcode = "1"
    elif AD == 'a2':
        avdomain = "ad2"
        avcode = "2"
    elif AD == 'a3':
        avdomain = "ad3"
        avcode = "3"

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

    subnetheader = NetTemplate.format(cidrname, srccidr, srcadd, region, avcode, cidrname, compartment, region, srcadd, region, region, region, region, seclistname1, seclistname1, seclistname1)
    os.chdir('/Users/slahiri/NGCCDEVfiles')
    cwd = os.getcwd()
    print "1", cwd

    with open('%s.tf' % (srcadd), "a+") as subf:
        subnetlist = subnetheader
        subf.write(subnetlist)
        print("###############SUBNET {} IN REGION {} HAVING CIDR BLOCK {} AND IN VCN {} HAS BEEN CREATED".format(srcadd, region, srccidr, vcn))


