import argparse
import re

if __name__ == '__main__':

    #setup the arguements, this is -s or multiple -s they can take one or more values, they all are parse
    parser = argparse.ArgumentParser(description='Creates blank subnet and seclist files')
    parser.add_argument("-s", help="Excel Port Matrix", nargs='*', type=str, action="append", metavar="<seclist spreadsheet>", )
    args = parser.parse_args()

    #create an output file with the commands, we could run that file or use as a log
    #it's name is fixed, but we could make it an arguement
    outfile = open('removefile.txt','w')

    for currentfile in args.s:
        infile = open(currentfile[0], 'r')
        for line in infile:
            nameOfSeclist = line.split(',')[1].strip()
            if re.search('^oragit', nameOfSeclist):
                outfile.write("rm {}.tf\n".format(nameOfSeclist))
