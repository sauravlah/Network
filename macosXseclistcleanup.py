from collections import Counter
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


#####Create pattern for searching non empty vs unused seclists to match against net resources. If there is a match that means the seclist is being referenced on the net resource#####
search = os.path.join(src_lindir, "macgrep")
out_file2 = os.path.join(src_lindir, "macsearchout2")
patterns = [ r'^(oragit-phx1-net-\w+)',
             r'^(oragit-ash1-net-\w+)'
             r'^(oragit-phx2-net-\w+)'
             r'^(oragit-ash2-net-\w+)'
           ]
#####For input file macgrep search for all net resource references and output those seclist entries to a file 'out_file2' and then do some formatting#####
with open("out_file2", 'w') as fout:
    with open(search, "r+") as foutpattern:
        for pattern in patterns:
            for line in foutpattern:
                linestr = ','.join(line)
                match = re.search(pattern,line)
                if match:
                    x = re.sub('^oragit-phx1-net.*\${oci_core_security_list.', '', line)
                    x = re.sub(r'\.id}\"\,', '', x)
                    x = re.sub('^\[', '', x)
                    x = re.sub('1\-[0-9]]', '', x)
                    fout.writelines(x)
                    x.split()
                    #print x

####Deletes duplicate lines from the file out_file2 for the seclists####
lines_seen = set() # holds lines already seen
outfile = open("out_file3", "w")
for line in open("out_file2", "r"):
    if line not in lines_seen: # not a duplicate
        outfile.write(line)
        lines_seen.add(line)

####Appends .tf extensions to the non duplicate seclist entries from file out_file3"#####

infile = open("out_file3", 'r')
outfile = open("pyout","a")

line = infile.readline()    # Invokes readline() method on file
while line:
  outfile.write(line.strip("\n")+".tf\n")
  line = infile.readline()

infile.close()
outfile.close()

###Comapring 2 files for a diff. One is the entireseclist names and then other one only those ones who have net reference###
with open(r'pyout','r') as pyout:
    with open(r'allseclists','r') as allseclists:
        with open(r'finalseclistremove','w+') as Newdata:
            pyout = [ x.strip('\n') for x in list(pyout) ] #1
            allseclists = [ x.strip('\n') for x in list(allseclists) ] #2

            for line in allseclists: #3
                if line not in pyout: #4
                     Newdata.write(line + '\n') #5




