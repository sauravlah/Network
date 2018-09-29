import re
import xlrd
import openpyxl
import os
from string import Template
import argparse

os.mkdir('/Users/slahiri/seclistrules')
parser = argparse.ArgumentParser(version='1.0')
parser.add_argument('-ir', nargs = 2, help = 'To find ingress rules corresponding to a subnet')
parser.add_argument('-er', nargs = 2, help = 'To find egress rules corresponding to a subnet')
parser.add_argument('-netsec', nargs = 3, help = '-netsec option To search all the seclist rules corresponding to CIDR input referencing a subnet')
parser.add_argument('-ipsec', nargs = 3, help = '-ipsec option to search all the seclist rules corresponding to a ip address referencing a subnet')
parser.add_argument('-netsecproto', nargs = 4, help = '-ipsec option to search all the seclist rules corresponding to CIDR referencing a subnet using particular protocol')
parser.add_argument('-netsecprotoport', nargs = 5, help = '-ipsec option to search all the seclist rules corresponding to CIDR referencing a subnet using particular protocol and port')
parser.add_argument('-irapp', nargs = 2, help = '-irapp option to look for ingress rules corresponding to an application name')
parser.add_argument('-erapp', nargs = 2, help = '-erapp option to look for egress rules corresponding to an application name')

args = parser.parse_args()

try:
    if args.ir:
        dir = args.ir[1]
        obj1 = ocinetwork_search(args.ir[0],dir)
        obj1.secingressrules()

try:
    if args.er:
        dir = args.er[1]
        obj1 = ocinetwork_search(args.er[0], dir)
        obj1.secegressrules()

class ocinetwork_search:
    def __init__(self, string2, path1,i=None):
        self.path1= path1
        self.string1 = string2
        self.i=i
        if self.i:
            string2 = string2.lower()
            self.string2= re.compile(string2)

    def secingressrules(self):
        file_number = 0
        files = [f for f in os.listdir(self.path1) if os.path.isfile(self.path1 +" / "+f)]
        for file in files:
            file_t = open(self.path1 + "/" + file)
            file_text = file_t.read()
            if self.i:
                file_text = file_text.lower()
            file_t.close()
            line = file_t.readline()
            cntrsrc = 0
            cntrdst = 0
            while line:
                #dstmatch = re.match('destination = *"[0-9].*', line.strip())
                srcmatch = re.match('source = *"[0-9].*', line.strip())
                secnamematch = re.match('(resource.*)("oragit-.*)-(sec)-(.*")', line.strip())
                #if dstmatch:
                 #   cntrdst = cntrdst + 1
                if srcmatch:
                    cntrsrc = cntrsrc + 1
                if secnamematch:
                    netname = re.sub(secnamematch.group(2), net, line)
                line = file_t.readline()
                os.chdir("/Users/slahiri/seclistrules")
                os.getcwd()
            with open('ingressrulescount', "a+") as g:
                g.write('The name of the file is {} and the number of ingress rules corresponding to that subnet {}'. format(file, cntrsrc, netname))
                #g.write('The name of the file is {} and the number of eggress rules corresponding to that subnet {}'.format(file, cntrdst, netname))

        print("The number of INGRESS RULES are {}".format(cntrsrc))
        print("The number of EGRESS RULES are {}".format(cntrdst))

    def secegressrules(self):
        file_number = 0
        files = [f for f in os.listdir(self.path1) if os.path.isfile(self.path1 +" / "+f)]
        for file in files:
            file_t = open(self.path1 + "/" + file)
            file_text = file_t.read()
            if self.i:
                file_text = file_text.lower()
            file_t.close()
            line = file_t.readline()
            cntrsrc = 0
            cntrdst = 0
            while line:
                dstmatch = re.match('destination = *"[0-9].*', line.strip())
                secnamematch = re.match('(resource.*)("oragit-.*)-(sec)-(.*")', line.strip())
                if dstmatch:
                    cntrdst = cntrdst + 1
                if secnamematch:
                    netname = re.sub(secnamematch.group(2), net, line)
                line = file_t.readline()
                os.chdir("/Users/slahiri/seclistrules")
                os.getcwd()
            with open('egressrulescount', "a+") as g:
                g.write('The name of the file is {} and the number of ingress rules corresponding to that subnet {}'. format(file, cntrsrc, netname))
                #g.write('The name of the file is {} and the number of eggress rules corresponding to that subnet {}'.format(file, cntrdst, netname))

        print("The number of EGRESS RULES are {}".format(cntrdst))


