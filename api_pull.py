#!/usr/local/bin/python3
import collections
import operator
import oci
import re
import string
import sys
import argparse
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

def list_instances(compartment_id, **kwargs):
    return ( paginate(compute.list_instances, compartment_id=compartment_id, **kwargs) )

def list_vnic_attachments(compartment_id, **kwargs):
    return ( paginate(compute.list_vnic_attachments, compartment_id=compartment_id, **kwargs) )

def get_vnic(vnic_id, **kwargs):
    ### return (paginate(compute.get_vnic_attachment, instance_id=instance_id, **kwargs))
    return ( network.get_vnic(vnic_id=vnic_id, **kwargs) )

def list_subnets(compartment_id, vcn_id=None, **kwargs):
    return ( paginate(network.list_subnets, compartment_id=compartment_id, vcn_id=vcn_id, **kwargs) )

def list_security_lists(compartment_id, vcn_id=None, **kwargs):
    return ( paginate(network.list_security_lists, compartment_id=compartment_id, vcn_id=vcn_id, **kwargs) )

def list_vcns(compartment_id, **kwargs):
    return ( paginate(network.list_vcns, compartment_id, **kwargs) )

def list_compartments(compartment_root, **kwargs):
    return ( paginate(identity.list_compartments, compartment_id=compartment_root, **kwargs) )

def list_regions(**kwargs):
    return ( paginate(identity.list_regions, **kwargs) )

def list_administrative_domains(compartment_root, **kwargs):
    return ( paginate(identity.list_availability_domains, compartment_id=compartment_root, **kwargs) )

def list_users(compartment_root, **kwargs):
    return ( paginate(identity.list_users, compartment_id=compartment_root, **kwargs) )


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Creates blank subnet and seclist files')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--ash', action='store_true',dest="ash")
    group.add_argument('--phx', action='store_false',dest="ash")
    args = parser.parse_args()

    if args.ash:
        config_str = "oragit-ash1"
    else:
        config_str = "oragit-phx1"
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
    for region in list_regions():
        print (region);
    for administrative_domain in list_administrative_domains(compartment_root):
        print (administrative_domain)
    ### for user in list_users(compartment_root):
    ###     print (user);
    ###
    ###     list security list and count the rules
    ###
    security_list_dict          = collections.defaultdict(str)
    instance_to_vnic_list_dict  = collections.defaultdict(list)
    subnet_list_dict            = collections.defaultdict(str)
    vnic_to_subnet_list_dict    = collections.defaultdict(str)
    vnic_to_ip_address_list_dict= collections.defaultdict(str)

    #create a workbook to record the information
    #wb = Workbook()
    #use the active sheet
    #wssubnet = wb.active
    #wssubnet.title = "Subnets"
    #wssubnet['A1'] = "Subnet Name"           #0
    #wssubnet['B1'] = "Display Name"          #1
    #wssubnet['C1'] = "CIDR Address"          #2
    #wssubnet['D1'] = "Availability Domain"   #3
    #wssubnet['E1'] = "Compartment"           #4
    #wssubnet['F1'] = "Region"                #5
    output = open("subnets.csv","w")
    
    ###
    ###     iterate through compartments and list subnets/seclists, and instances
    ###
    for compartment in list_compartments(compartment_root):
        #print ('     {:40} {:15} {}'.format(compartment.name,compartment.lifecycle_state,compartment.id))
        #for vcn in list_vcns(compartment.id):
            #print ('     **VCN:  {:40} {:20} {}'.format(vcn.display_name,vcn.cidr_block,vcn.id))
        for subnet in list_subnets(compartment.id,vcn_id):
            if region.name == 'us-phoenix-1':
                regionName = 'phx1'
            elif region.name == 'us-ashburn-1':
                regionName = 'ash1'
            else:
                regionName = 'unknown'
            matchAD = re.search('.*-AD-(\d)',subnet.availability_domain)
            ADNumber = matchAD.group(1)
            print ('{},{},{},{},{},{},{}'.format(subnet.display_name,subnet.cidr_block,regionName,ADNumber,compartment.name,regionName,vcn_id))
            #create the line
            output.write("{},{},{},{},{},{}\n".format(subnet.display_name,subnet.display_name,subnet.cidr_block,ADNumber,compartment.name,regionName,vcn_id))
            #line = (subnet.display_name,subnet.display_name,subnet.cidr_block,ADNumber,compartment.name,regionName)
            #wssubnet.append(line)
           
    output.close()
    #wb.save("subnets.xls")
