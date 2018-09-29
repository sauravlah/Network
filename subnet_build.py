#!/usr/local/bin/python3
import collections
import oci
import re
import string
import sys
import argparse
import netaddr
#from openpyxl import Workbook
###
###
###
def print_status(char):
    sys.stdout.flush()
    sys.stdout.write(char)

def paginate(operation, *args, **kwargs):
    while True:
        response = operation(*args, **kwargs)
        for value in response.data:
            yield value
        kwargs["page"] = response.next_page
        if not response.has_next_page:
            break
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
def list_instances(compartment_id, **kwargs):
    return ( paginate(compute.list_instances, compartment_id=compartment_id, **kwargs))

def list_vnic_attachments(compartment_id, **kwargs):
    return ( paginate(compute.list_vnic_attachments, compartment_id=compartment_id, **kwargs))

def get_vnic(vnic_id, **kwargs):
    ### return (paginate(compute.get_vnic_attachment, instance_id=instance_id, **kwargs))
    return ( network.get_vnic(vnic_id=vnic_id, **kwargs))

def list_subnets(compartment_id, vcn_id=None, **kwargs):
    return ( paginate(network.list_subnets, compartment_id=compartment_id, vcn_id=vcn_id, **kwargs))

def list_security_lists(compartment_id, vcn_id=None, **kwargs):
    return ( paginate(network.list_security_lists, compartment_id=compartment_id, vcn_id=vcn_id, **kwargs))

def list_vcns(compartment_id, **kwargs):
    return ( paginate(network.list_vcns, compartment_id, **kwargs) )

def list_compartments(compartment_root, **kwargs):
    return ( paginate(identity.list_compartments, compartment_id=compartment_root, **kwargs))

def list_regions(**kwargs):
    return ( paginate(identity.list_regions, **kwargs) )

def list_administrative_domains(compartment_root, **kwargs):
    return ( paginate(identity.list_availability_domains, compartment_id=compartment_root, **kwargs))

def list_users(compartment_root, **kwargs):
    return ( paginate(identity.list_users, compartment_id=compartment_root, **kwargs) )


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Creates blank subnet and seclist files')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--ash', action='store_true',dest="ash")
    group.add_argument('--phx', action='store_false',dest="phx")
    group.add_argument('--fra', action = 'store true', dest= "fra")
    group.add_argument('--scompart', action = 'store true', dest = "sandbox")
    group.add_argument('--pcompart', action='store true', dest="prod")

    args = parser.parse_args()

    if args.ash:
        config_str = "oragit-ash1"
    elif args.fra:
        config_str = "oragit-fra1"
    else:
        config_str = "oragit-phx1"
    if args.sandbox:
        compartment = "sandbox"
    else:
        compartment = "prod"
    ###
    ###
    ###
    config              = oci.config.from_file( "~/.oci/config", config_str)
    compartment_root    = config["tenancy"]
    vcn_id              = config["vcn"]
    compute             = oci.core.compute_client.ComputeClient(config)
    identity            = oci.identity.identity_client.IdentityClient(config)
    network             = oci.core.virtual_network_client.VirtualNetworkClient(config)
    ###
    ###
    ###
dirlinlist = os.listdir("/app/bmcs/terraform/deployments/global/tenancy/oragit/networks")
target_dir = "/Users/slahiri/oraclebmc/seclist_dormant"
srcash1_dir = "/Users/slahiri/oraclebmc/seclist_dormant"
srcphx1_dir = "/Users/slahiri/oraclebmc/seclist_dormant"

print os.path.exists("/app/bmcs/terraform/deployments/global/tenancy/oragit/networks")

#####Create pattern for searching non empty vs unused seclists to match against net resources. If there is a match that means the seclist is being referenced on the net resource#####
class subnetres:
    def __init__(self, Name, DisplayName, Region, CIDR, Compartment, AD, VCN, dhcpOptions):
        self.name = Name
        self.displayName = DisplayName
        self.region = Region
        self.cidr = CIDR
        self.ad = AD
        self.vcn = VCN
        self.dhcpOptions = dhcpOptions
        self.compartment = Compartment
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

        # cidrname = 0
        # cidradd = 1
        # subnetname = 2
        # region=3
        # ad=4
        # compartment=5
        # seclistname=6
        # displayname=7
        # outputs the terraform file declaration
    def oci_templates(self, template):
            const.NetTemplate = """variable "{0}"	{{ default = "{1}" }}
            
            
            resource "oci_core_subnet" "{2}"
            {{
                availability_domain = "{{var.oragit-{3}-ad{4} }}"
            cidr_block = "{{var.{0} }}"
            compartment_id = "{{var.{5} }}"
            dhcp_options_id = "{{oci_core_dhcp_options.oragit-{3}-dhcp1.id}}"
            display_name = "{7}"
            vcn_id = "{{oci_core_virtual_network.oragit-{3}-vcn1.id}}"
            route_table_id = "{{oci_core_route_table.oragit-{3}-rt1.id}}"
            security_list_ids = [
                "{{oci_core_security_list.oragit-{3}-sec-vcn1-prod-general1.id}}",
                "{{oci_core_security_list.oragit-{3}-sec-vcn1-prod-general2.id}}",
                "{{oci_core_security_list.{6}-1.id}}",
                "{{oci_core_security_list.{6}-2.id}}",
                "{{oci_core_security_list.{6}-3.id}}",
            ]
            }}
            """
            return const.NetTemplate

    def oci_region(self, region):
        pattern_region = [r'lon[0-9]',
                          r'ash[0-9]',
                          r'phx[0-9]',
                          r'fra[0-9]'
                         ]
        with open("subnetinput.txt", "r+") as subnetin:
             for line in subnetin:
                 if re.search(pattern_region, line):
                     region = match.group
                 return self.region

    def oci_subnetmask(self, cidrmask):
        pattern_CIDR = [r'\d+$']
        with open("subnetinput.txt", "r+") as subnetin:
            for pattern in patterns:
                for line in subnetin:
                    if re.search(pattern_CIDR, line):
                        return match.group
    def oci_CIDR(self, cidr):
        pattern_CIDR = [r'\d+\.\d+\.\d+\.\d+']
        with open("subnetinput.txt", "r+") as subnetin:
            for pattern in patterns:
                for line in subnetin:
                    if re.search(pattern_CIDR, line):
                        return match.group

    def oci_cidr_exist(self, string):
        patterns = [r'\s.*\d+',
                    r'^oragit.*\s'
                   ]
        for compartment in list_compartments(compartment_root):
            for subnet in list_subnets(compartment.id, vcn_id):
                if IPNetwork(subnetres(CIDR)).cidr == IPNetwork(subnet):
                    return True
                else:
                    return False

    def oci_ipFormatCheck(self, ip_str):
        pattern = r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        if re.match(pattern, ip_str):
            return True
        else:
            return False

    def oci_ad(self,string):
        with open("subnetinput.txt", "r+") as subnetin:
            for line in subnetin:
                match = re.search(r'ad[0-9]', line)
                return match.group()

    def oci_outputSubnetFile(self):
        patterns = [r'\s.*\d+',
                    r'^oragit.*\s'
                    ]
        with open("subnetinput.txt", "r+") as subnetin:
            with open("subnetoutput", "a+") as subnetout:
                for pattern in patterns:
                    for line in subnetin:
                        linestr = ','.join(line)
                        matchcidr = re.search(r'\s.*\d+', line)
                        matchstring = re.search(r'^oragit.*\s', line)
                    if subnetres(cidr_exist):
                        if subnetres(__ipFormatCheck()):
                            cidrname   = re.sub('-net', 'cidr', matchstring)
                            cidr   = subnetres(self.oci_CIDR())
                            net    = matchstring.re.pattern
                            region = subnetres(self.oci_region)
                            AD     = subnetres(self.oci_ad)
                            COMP   = compartment
                            display_name = self.name
                            seclistname = re.sub('-net-', '-sec-', self.name)

                            subnetout.write(NetTemplate.format(self.cidrname, self.cidr, self.net, self.region, self.AD,
                                        self.COMP, self.display_name, self.seclistname + '\n\n\n\n'))
                            return NetTemplate.formatconst.NetTemplate.format(self.cidrname, self.cidr, self.net, self.region, self.AD,
                                        self.COMP, self.display_name, self.seclistname + '\n\n\n\n')