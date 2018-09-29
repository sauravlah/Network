#!/usr/bin/python
#NAME: filenamealter.py
#Purpose: Takes a GIS Port matrix, and spits out a set of terraform files for SecLists
#Author: C.R.Chapman 
majorVersion = 0
minorVersion = 1
patchVersion = 'b'
#
#TODO: Detect if the -3 file has rules in and highlight this

import os
import re

searchstring = re.compile("(.*)-1.tf")
ad2searchstring = re.compile("^(oragit-(?:ash1|phx1)-sec-vcn1-)(.*)-2$")

#mv oragit-phx1-sec-vcn1-prod-ngcc-tools-blackchair-internal-db1-1.tf oragit-phx1-sec-vcn1-prod-ngcc-tools-blackchair-internal-db1.tf
#mv oragit-phx1-sec-vcn1-nonprod-ngcc-tools-gpia-internal-mt1-1.tf oragit-phx1-sec-vcn1-nonprod-ngcc-tools-gpia-internal-mt1.tf

#("",""),
singlerenamelist = (("oragit-phx1-sec-vcn1-prod-ngcc-tools-blackchair-internal-db1-1","oragit-phx1-sec-vcn1-prod-ngcc-tools-blackchair-internal-db1"),
                    ("oragit-phx1-sec-vcn1-nonprod-ngcc-tools-gpia-internal-mt1-1","oragit-phx1-sec-vcn1-nonprod-ngcc-tools-gpia-internal-mt1"),
                    ("oragit-phx1-sec-vcn1-ad1-prod-ngcc-tools-internal-oob1-1","oragit-phx1-sec-vcn1-ad1-prod-ngcc-tools-internal-oob1"),
                    ("oragit-phx1-sec-vcn1-prod-ngcc-tools-blackchair-internal-mt1-1","oragit-phx1-sec-vcn1-prod-ngcc-tools-blackchair-internal-mt1"),
                    ("oragit-phx1-sec-vcn1-dev-ngcc-internal-voice1-1","oragit-phx1-sec-vcn1-dev-ngcc-internal-voice1"),
                    ("oragit-phx1-sec-vcn1-dev-ngcc-internal-mt1-ms1-1","oragit-phx1-sec-vcn1-dev-ngcc-internal-mt1-ms1"),
                    ("oragit-phx1-sec-vcn1-dev-ngcc-external-mt1-1","oragit-phx1-sec-vcn1-dev-ngcc-external-mt1"),
                    ("oragit-phx1-sec-vcn1-dev-ngcc-internal-mt1-1","oragit-phx1-sec-vcn1-dev-ngcc-internal-mt1"),
                    ("oragit-phx1-sec-vcn1-dev-ngcc-internal-db1-1","oragit-phx1-sec-vcn1-dev-ngcc-internal-db1"),
                    )

#"",
removefiles = ("oragit-phx1-sec-vcn1-prod-ngcc-tools-blackchair-internal-mt1-3",
               "oragit-phx1-sec-vcn1-nonprod-ngcc-tools-gpia-internal-mt1-3",
               "oragit-phx1-sec-vcn1-dev-ngcc-internal-voice1-2","oragit-phx1-sec-vcn1-dev-ngcc-internal-voice1-3",
               "oragit-phx1-sec-vcn1-dev-ngcc-internal-mt1-ms1-2","oragit-phx1-sec-vcn1-dev-ngcc-internal-mt1-ms1-3",
               "oragit-phx1-sec-vcn1-dev-ngcc-external-mt1-2","oragit-phx1-sec-vcn1-dev-ngcc-external-mt1-3",
               "oragit-phx1-sec-vcn1-dev-ngcc-internal-mt1-3",
               "oragit-phx1-sec-vcn1-dev-ngcc-internal-db1-2","oragit-phx1-sec-vcn1-dev-ngcc-internal-db1-3",
               )

ad2seclist = ("oragit-phx1-sec-vcn1-dev-ngcc-internal-mt1-2",
              "oragit-phx1-sec-vcn1-nonprod-ngcc-tools-gpia-internal-mt1-2",
              "oragit-phx1-sec-vcn1-prod-ngcc-tools-blackchair-internal-mt1-2",
              )

def rules(filestr):
    fh = open(filestr, 'r')
    for line in fh:
        if re.search('^\s+(destination|source)', line):
            return True
    return False

for oldfilename, newfilename in singlerenamelist:
    
    #os.rename(oldfilename+'tf', newfilename+'tf')
    try:
        if not os.path.exists(oldfilename+'.tf'):
            continue
        oldfile = open(oldfilename+'.tf','r')
        newfile = open(newfilename+'.tf','w')
    except Exception as e:
        print "Unable to alter file: {}".format(e)
    else:
        for line in oldfile:
            newfile.write(line.replace(oldfilename, newfilename))
        oldfile.close()
        newfile.close()
        os.remove(oldfilename+'.tf')
        print "Moved {} to {}".format(oldfilename, newfilename)
        

for removefile in removefiles:
    try:
        if os.path.exists(removefile+'.tf'):
            if rules(removefile+'.tf'):
                print "{} contains rules, but needs to be destroyed".format(removefile+'.tf')
                exit(-1)
            os.remove(removefile+'.tf')
            print "Removed file {}".format(removefile)
    except Exception as e:
        print "Unable to delete file: {} error {}".format(removefile,e)

for ad2file in ad2seclist:
    try:
        #see if the file is there
        if os.path.exists(ad2file+'.tf'):
            continue
        
        match = ad2searchstring.search(ad2file)
        file1str = match.group(1)+'ad1-'+match.group(2)
        file2str = match.group(1)+'ad2-'+match.group(2)

        oldfile = open(ad2file+".tf",'r')
        print "Creating files {}, {}".format(file1str,file1str)
        newfile1 = open(file1str+'.tf','w')
        newfile2 = open(file2str+'.tf','w')
        #if not ignore it
    except OSError as e:
        print "Unable to open files {}".format(e)
    else:
        #else we move the file to new filename
        for line in oldfile:
            newfile1.write(line.replace(ad2file, file1str))
            newfile2.write(line.replace(ad2file, file2str))
        #cleanup
        oldfile.close()
        newfile1.close()
        newfile2.close()
        os.remove(ad2file+'.tf')

        print "Moved {} to {} and {}".format(ad2file+'.tf', file1str+'.tf', file2str+'.tf')
        

