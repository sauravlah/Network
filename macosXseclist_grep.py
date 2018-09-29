import argparse
import collections
import re
import sys
import os
import subprocess
from os import listdir
from commands import getoutput
import pprint

#### LOGIC:
###OPEN INPUT SEARCH FILE IN READ MODE (SECLIST REFERENCE)
#### READ EACH LINE FROM THE FILE ABOVE AND USE IT AS A PATTERN FOR GREP/PATTERN MATCHING AGAINST ALL THE FILES IN THE CURRENT DIRECTORY"
#### ONCE A MATCH IS FOUND IF THERE IS PATTERN '-NET-' IN THE OUTPUT PLEASE DONT DO ANYTHING.
#### OIHERWISE, MOVE/DELETE THE FILE

dirlist = os.listdir("/Users/slahiri/oraclebmc/seclist_dormant")
src_dir = "/Users/slahiri/oraclebmc/seclist_dormant"
target_dir = "/Users/slahiri/oraclebmc/seclist_dormant"
pattern = [r'\w*oragit*\w*',  # word containing 't'
           r'\b*\w+',  # 'oragit' at start of word
           ]
print os.path.exists("/Users/slahiri/oraclebmc/seclist_dormant")
if os.path.exists("/Users/slahiri/oraclebmc/seclist_dormant"):

    for f in os.listdir(src_dir):
        input_file = os.path.join(src_dir, "file_list")
        out_file = os.path.join(src_dir, "outputfile")
        with open(input_file, "r+") as fin:
            with open(out_file, "w") as fout:
                for line in fin:
                    line = line.split(' ')
                    MAX = len(line)
                    y = len(line[MAX - 1].split('-'))
                    x = (line[MAX - 1].split('-'))
                    del x[y - 1:y]
                    #print x
                    str_keyword = '-'.join(x)
                    fout.write(str_keyword + '\n')

out_file = os.path.join(src_dir, "outputfile")

with open(out_file, "r+") as fout:
    for line in fout:
        print (line)
        linestr = line.split('\n')
        command = ['grep']
        command.append('line')
        command.append('*.tf')
        (out,err) = subprocess.Popen(command, stdout=subprocess.PIPE).communicate()
        print out
        print err


