import os
import openpyxl
from openpyxl import Workbook
import time
import re
import const
import logging
import xlrd

excel_doc=openpyxl.load_workbook('/Users/slahiri/NGCCUPM.xlsx')
sheet_names = excel_doc.get_sheet_names()
print(sheet_names)
print type(excel_doc)
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

# AD OCI region names to internal naming construction
ad_list = dict()
ad_list['us-ashburn-1'] = 'ash1'
ad_list['eu-frankfurt-1'] = 'fra1'
ad_list['us-phoenix-1'] = 'phx1'

patterns = [ r"${oragit-phx1-net.*",
             r'(\w*"oragit-ash1-net\w*)',
             r'(\w*"oragit-ash1-net\w*)',
           ]
regexnetsrc=r"oragit-([a-z])+([0-9])-net-vcn1-.*"
#regexnetsrcad2=r"oragit-([a-z])+([0-9])-net-vcn1-ad2.*"
regexsrccidr=r"([0-9])+.*"


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


sheet = excel_doc.get_sheet_by_name('DEV PM 4.10')
multiple_cells = sheet['A']
for row in sheet.iter_rows(min_row=8, min_col=1, max_row=200, max_col=8):
    for cell in row:
        if re.search(regexnetsrc, str(cell.value)):
            match = re.search(regexnetsrc, str(cell.value))
            netsrc = match.group(0)
            netsrcentry = re.sub("\[u", '', netsrc)
            netsrclist = netsrc.split(' ')

            print netsrcentry
            print netsrclist

        if re.search(regexsrccidr, str(cell.value)):
            match1 = re.search(regexsrccidr, str(cell.value))
            srccidr = match1.group(0)
            print srccidr
































