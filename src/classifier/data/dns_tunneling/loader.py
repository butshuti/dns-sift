import numpy, csv, shutil
from os import listdir, makedirs
from os.path import exists, isfile, isdir, join, dirname, realpath, basename

def parse_file(fname):
    with open(fname, 'rb') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        ret = []
        for row in reader:
            ret.append([float(x) for x in row[:-1]])
    return ret

def add_file_to_model_dir(filename, dirName):
    if not exists(dirName):
        makedirs(dirName)
    if not isdir(dirName):
        raise Exception("No such directory: {}.".format(dirName))
    elif not isfile(filename):
        raise Exception("No such filr: {}.".format(filename))
    dstFileName = join(dirName, basename(filename))
    if isfile(dstFileName):
        raise Exception("File with same name already exists: {}".format(dstFileName))
    shutil.copyfile(filename, dstFileName)
    return

class DataSet(object):
    def __init__(self, modelDir=None):
        self.test_samples = None
        self.training_samples = None
        self.load(modelDir)
        
    def load(self, modelDir):
        if modelDir is None:
            modelDir = dirname(realpath(__file__))
        pos_dataset_dir = join(modelDir, 'normal')
        neg_dataset_dir = join(modelDir, 'anomalous')        
        posfiles = [join(pos_dataset_dir, f) for f in listdir(pos_dataset_dir) if (isfile(join(pos_dataset_dir, f)) and f.endswith('.csv'))]
        negfiles = [join(neg_dataset_dir, f) for f in listdir(neg_dataset_dir) if (isfile(join(neg_dataset_dir, f)) and f.endswith('.csv'))]
        training_samples = []
        test_samples = []
        feat_len = -1
        for f in posfiles:
            dat = parse_file(f)
            feat_len = max([len(row) for row in dat])
            dat = [(row, (basename(f), 'P')) for row in dat if len(row) == feat_len]
            training_samples.extend(dat)
            test_samples.extend(dat)
        for f in negfiles:
            dat = parse_file(f)
            dat = [(row, (basename(f), 'N')) for row in dat if len(row) == feat_len]            
            test_samples.extend(dat)  
        training_samples = training_samples[0::10]
        observations = test_samples[:]
        self.training_samples = numpy.array(training_samples)
        self.test_samples = numpy.array(observations)
    
    def loadDs(self, path, tag):
        from os.path import basename
        dat = parse_file(path)
        return numpy.array([(row, (basename(path), tag)) for row in dat])
        
    def loadDsDir(self, dirPath, tag):
        from os.path import basename
        if not isdir(dirPath):raise Exception("No such directory: {}.".format(dirPath))
        files = [join(dirPath, f) for f in listdir(dirPath) if (isfile(join(dirPath, f)) and f.endswith('.csv'))]
        ret = []
        for f in files:
        		dat = parse_file(f)
        		dat = [(row, (basename(f), tag)) for row in dat]
        		ret.extend(dat)
        return numpy.array(ret)
    
if __name__ == '__main__':
    DataSet()
