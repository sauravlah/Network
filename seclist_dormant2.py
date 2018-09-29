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

dirlinlist = os.listdir("/home/salahiri/seclist_dormant")
#dirwinlist = os.listdir("C:/Users/salahiri/Documents/Oracle/Devops/oraclebmc/seclist_dormant")
src_lindir = "/home/salahiri/seclist_dormant"
#src_windir = "C:\Users\salahiri\Documents\Oracle\Devops\oraclebmc\seclist_dormant"
target_lindir = "/home/salahiri/seclist_dormant"
#target_windir = "C:\Users\salahiri\Documents\Oracle\Devops\oraclebmc\seclist_dormant"

pattern = [r'\w*oragit*\w*',  # word containing 't'
           r'\b*\w+',  # 'oragit' at start of word
           ]
print os.path.exists("\home\salahiri\seclist_dormant")
#print os.path.exists("C:\Users\salahiri\Documents\Oracle\Devops\oraclebmc\seclist_dormant")
if os.path.exists("\home\salahiri"):
#if os.path.exists("C:\Users\salahiri\Documents\Oracle\Devops\oraclebmc\seclist_dormant"):

    for f in os.listdir(src_lindir):
        input_file = os.path.join(src_lindir, "unused_seclists.py20171219205715.log")
        out_file = os.path.join(src_lindir, "outputfile.txt")
        with open(input_file, "r+") as fin:
            with open(out_file, "w") as fout:
                for line in fin:
                    line = line.split(',')
                    MAX = len(line)
                    y = len(line[MAX-1].split('-'))
                    x = (line[MAX-1].split('-'))
                    del x[y-1:y]
                    print x
                    str_keyword = '-'.join(x)
                    fout.write(str_keyword + '\n')

search = os.path.join(src_lindir, "seclist2")
out_file = os.path.join(src_lindir, "outputsearchresult.txt")
patterns = [ r'"${oragit-phx1-net.*',
             r'(\w*"oragit-phx1-net\w*)',
             r'(\w*"oragit-ash1-net\w*)',
           ]
with open(search, "r+") as foutpattern:
    for pattern in patterns:
        for line in foutpattern:
            linestr = ','.join(line)
            mtch = re.search(pattern, linestr)
            print 'Found "%s" in "%s"' % \
                  (mtch.re.pattern, mtch.string)
            fout = open("out_file", "a+")
            fout.writelines(mtch)
