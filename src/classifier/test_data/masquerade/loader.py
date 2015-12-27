import numpy, csv, os

"""
This data set was provided by Schonlau (www.schonlau.net) for evaluation of intrusion detection methods.
The data consist of 50 files corresponding to one user each. Each file contains 15,000 commands (audit data generated with acct). 
The first 5000 commands for each user do not contain any masqueraders and are intended as training data. 
The next 10,000 commands can be thought of as 100 blocks of 100 commands each. 
They are seeded with masquerading users, i.e. with data of another user not among the 50 users.
At any given block after the initial 5000 commands a masquerade starts with a probability of 1%. 
If the previous block was a masquerade, the next block will also be a masquerade with a probability of 80%. About 5% of the test data contain masquerades.  
"""
TEST_DATA_FILE = "masquerade_summary.txt"
"""
File containing a matrix of locations of masquerades (http://www.schonlau.net/masquerade/masquerade_summary.txt)
This file contains 100 rows and 50 columns. Each column corresponds to one of the 50 users. 
Each row corresponds to a set of 100 commands, starting with command 5001 and ending with command 15000. 
The entries in the files are 0 or 1. 
0 means that the corresponding 100 commands are not contaminated by a masquerader. 
1 means they are contaminated. 
"""
TEST_BLOCKS_START_OFFS = 5000
TEST_LEN = 15000
NUM_USERS = 50
BLOCK_LEN = 100

def parse_features(baseDir):
    ret = []
    for idx in range(NUM_USERS):
        fname = os.path.join(baseDir, "User{}".format(idx+1))
        with open(fname) as f:
            ret.extend([line.strip('\n') for line in f.readlines()])
            f.close()
    return list(set(ret))

def get_feature_repr(ft, ft_map):
    try:
        return ft_map.index(ft)
    except ValueError:
        return -1
    
def get_feature_hash(ft, ft_map, siz):
    ret = get_feature_repr(ft, ft_map)
    return ret%siz

def get_bow_repr(doc, voc, ft_vec_size):
    tmp = {}
    doc = [get_feature_hash(w, voc, ft_vec_size) for w in doc]
    voc = [get_feature_hash(w, voc, ft_vec_size) for w in voc]
    for word in voc:
        tmp[word] = 0
    for word in doc:
        tmp[word] = 1 + tmp.get(word, 0)
    ret = numpy.array(tmp.values())
    return ret

def class_symbol(lbl):
    if int(lbl) == 1: return 'P'
    return 'N'

def class_legend(disp_lbl, lbl):
    if int(lbl) == 1: return "Is-{}".format(disp_lbl)
    return "Not-{}".format(disp_lbl)

def parse_profile(userIdx, features, summary_matrix, baseDir, ft_vec_size):
    commands = []
    fname = os.path.join(baseDir,"User{}".format(userIdx+1))
    with open(fname) as f:
        commands = [line.strip('\n') for line in f.readlines()]
        f.close()
    userLabel = 'User {}'.format(userIdx+1)
    profile_commands = commands[:TEST_BLOCKS_START_OFFS]
    profile_command_blocks = [profile_commands[i*BLOCK_LEN:(i*BLOCK_LEN)+BLOCK_LEN] for i in range(len(profile_commands)/BLOCK_LEN)]
    profile = []
    for block in profile_command_blocks:
        profile.append((get_bow_repr(block, features, ft_vec_size), 
                        (class_legend(userLabel, 1), 'P')))
    test_commands = commands[TEST_BLOCKS_START_OFFS:]
    test_command_blocks = [test_commands[i*BLOCK_LEN:(i*BLOCK_LEN)+BLOCK_LEN] for i in range(len(test_commands)/BLOCK_LEN)]
    observations = profile[:]
    for idx in range(len(test_command_blocks)):
        observations.append((get_bow_repr(test_command_blocks[idx], features, ft_vec_size), 
                             (class_legend(userLabel, summary_matrix[idx][userIdx]), class_symbol(summary_matrix[idx][userIdx]))))
    return (profile, observations)

def parse_summary(fname):
    with open(fname, 'rb') as csvfile:
        reader = csv.reader(csvfile, delimiter=' ')
        ret = []
        for row in reader:
            ret.append(row)
    return ret

class DataSet(object):
    def __init__(self, ft_vec_size=12):
        self.test_samples = None
        self.training_samples = None
        self.ft_vec_siz = ft_vec_size
        self.baseDir = '/home/butshuti/research/session_profile/test_data/masquerade'
        self.summary_matrix = parse_summary(os.path.join(self.baseDir, TEST_DATA_FILE))
        self.features = parse_features(self.baseDir)
        self.loaded = {}
        #self.load_user(0)
        
    def load(self):
        observations = [parse_profile(idx, self.features, 
                                      self.summary_matrix, 
                                      self.baseDir, self.ft_vec_siz) for idx in range(NUM_USERS)]
        self.training_samples = numpy.array([x[0] for x in observations])
        self.test_samples = numpy.array([x[1] for x in observations])
        
    def load_user(self, userIdx):   
        if userIdx in self.loaded:
            return
        self.loaded[userIdx] = parse_profile(userIdx, self.features, 
                                     self.summary_matrix, self.baseDir, self.ft_vec_siz)
        observations = []
        for obs in self.loaded.values():
            observations.extend(obs)
        self.training_samples = numpy.array(observations[0])
        self.test_samples = numpy.array(observations[1])            
        