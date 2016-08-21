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
        from os import listdir
        from os.path import isfile, join, dirname, realpath, basename
        pos_dataset_dir = join(dirname(realpath(__file__)), 'legit')
        neg_dataset_dir = join(dirname(realpath(__file__)), 'anomalous')
        posfiles = [join(pos_dataset_dir, f) for f in listdir(pos_dataset_dir) if isfile(join(pos_dataset_dir, f))]
        negfiles = [join(neg_dataset_dir, f) for f in listdir(neg_dataset_dir) if isfile(join(neg_dataset_dir, f))]
        training_samples = []
        test_samples = []
        for f in posfiles:
            dat = parse_file(f)
            dat = [(row, (basename(f), 'P')) for row in dat]
            training_samples.extend(dat)
            test_samples.extend(dat)
        for f in negfiles:
            dat = parse_file(f)
            dat = [(row, (basename(f), 'N')) for row in dat]            
            test_samples.extend(dat)  
        training_samples = training_samples[0::10]
        observations = test_samples[:]
        self.training_samples = numpy.array(training_samples)
        self.test_samples = numpy.array(observations)

if __name__ == '__main__':
    DataSet()