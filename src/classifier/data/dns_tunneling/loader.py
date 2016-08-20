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
        browsers = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'browsers.csv')
        alexa = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'namebench_alexa.csv')
        firefox = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'namebench_firefox.csv')
        iodine = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'iodine.csv')
        dnscat = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'dnscat.csv')
        browsers_samples = parse_file(browsers)
        alexa_samples = parse_file(alexa)
        firefox_samples = parse_file(firefox)
        iodine_samples = parse_file(iodine)
        dnscat_samples = parse_file(dnscat)
        training_samples = [([float(x) for x in p], ('browsers', 'P')) for p in browsers_samples[0::10]]
        observations = [([float(x) for x in p], ('browsers', 'P')) for p in browsers_samples]
        alexa_samples = [([float(x) for x in p], ('namebench_Alexa', 'P')) for p in alexa_samples]
        firefox_samples = [([float(x) for x in p], ('namebench_Firefox', 'P')) for p in firefox_samples]
        iodine_samples = [([float(x) for x in p], ('iodine', 'N')) for p in iodine_samples]
        dnscat_samples = [([float(x) for x in p], ('dnscat', 'N')) for p in dnscat_samples]
        observations.extend(alexa_samples)
        observations.extend(firefox_samples)
        observations.extend(iodine_samples)
        observations.extend(dnscat_samples)
        self.training_samples = numpy.array(training_samples)
        self.test_samples = numpy.array(observations)        