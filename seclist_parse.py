for f in os.listdir(src_lindir):
    input_file = os.path.join(src_lindir, "unused_seclists.py20171219205715.log")
    out_file = os.path.join(src_lindir, "outputfile.txt")
    with open(input_file, "r+") as fin:
        with open(out_file, "w") as fout:
            for line in fin:
                line = line.split(',')
                MAX = len(line)
                y = len(line[MAX - 1].split('-'))
                x = (line[MAX - 1].split('-'))
                del x[y - 1:y]
                print x
                str_keyword = '-'.join(x)
                fout.write(str_keyword + '\n')