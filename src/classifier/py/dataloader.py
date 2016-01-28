import csv

def parse_file(fname):
    with open(fname, 'rb') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        ret = []
        for row in reader:
            ret.append(row)
    return ret