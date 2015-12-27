import numpy, csv

def parse_file(fname):
    with open(fname, 'rb') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        ret = []
        for row in reader:
            ret.append(row)
    return ret

class DataSet(object):
    def __init__(self):
        self.test_samples = None
        self.training_samples = None
        self.load()
        
    def load(self):
        import os
        normal = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'normal.csv')
        iodine = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'iodine.csv')
        dnscat = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'dnscat.csv')
        training_samples = parse_file(normal)
        iodine_samples = parse_file(iodine)
        dnscat_samples = parse_file(dnscat)
        observations = [([float(x) for x in p], ('normal DNS', 'P')) for p in training_samples]
        iodine_samples = [([float(x) for x in p], ('iodine', 'N')) for p in iodine_samples]
        dnscat_samples = [([float(x) for x in p], ('dnscat', 'N')) for p in dnscat_samples]
        observations.extend(iodine_samples)
        observations.extend(dnscat_samples)
        self.training_samples = numpy.array([([float(x) for x in p], 'N') for p in training_samples])
        self.test_samples = numpy.array(observations)        