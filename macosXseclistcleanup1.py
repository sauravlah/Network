import collections
import re
import sys
import os
from os import listdir
import pprint


#### LOGIC:
###OPEN INPUT SEARCH FILE IN READ MODE (SECLIST REFERENCE)
#### READ EACH LINE FROM THE FILE ABOVE AND USE IT AS A PATTERN FOR GREP/PATTERN MATCHING AGAINST ALL THE FILES IN THE CURRENT DIRECTORY"
#### ONCE A MATCH IS FOUND IF THERE IS PATTERN '-NET-' IN THE OUTPUT PLEASE DONT DO ANYTHING.
#### OIHERWISE, MOVE/DELETE THE FILE

dirlinlist = os.listdir("/Users/slahiri/oraclebmc/seclist_dormant")
#dirwinlist = os.listdir("C:/Users/salahiri/Documents/Oracle/Devops/oraclebmc/seclist_dormant")
src_lindir = "/Users/slahiri/oraclebmc/seclist_dormant"
#src_windir = "C:\Users\salahiri\Documents\Oracle\Devops\oraclebmc\seclist_dormant"
target_lindir = "/Users/slahiri/oraclebmc/seclist_dormant"
#target_windir = "C:\Users\salahiri\Documents\Oracle\Devops\oraclebmc\seclist_dormant"

print os.path.exists("/Users/slahiri/oraclebmc/seclist_dormant")
#print os.path.exists("C:\Users\salahiri\Documents\Oracle\Devops\oraclebmc\seclist_dormant")
if os.path.exists("\Users\slahiri\oraclebmc"):
#if os.path.exists("C:\Users\salahiri\Documents\Oracle\Devops\oraclebmc\seclist_dormant"):

    for f in os.listdir(src_lindir):
        input_file = os.path.join(src_lindir, "seclistout")
        out_file = os.path.join(src_lindir, "outputfile1.txt")
        with open(input_file, "r+") as fin1:
            with open(out_file, "w") as fout1:
                for line in fin1:
                    line = line.split()
                    MAX = len(line)
                    print MAX
                    y = len(line[MAX-1].split('-'))
                    x = (line[MAX-1].split('-'))
                    del x[y-1:y]
                    print x
                    str_keyword = '-'.join(x)
                    fout1.write(str_keyword + '\n')
