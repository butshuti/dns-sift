from dnssift.py.classifier import *
from dnssift.py.debug import *
import dnssift.configutils as cfg
from threading import Thread
import sys, os, socket, time, random, numpy as np
from os.path import expanduser

cfgParams = cfg.parseConf()
UDS_FILE_NAME = cfgParams["uds_sock_file"]
MODEL_DATA_DIR = cfgParams["model_data_dir"]
DUMMY_TOKEN = "no_token"
DUMMY_TOKEN_CONF = "{}=>{}".format(DUMMY_TOKEN, DUMMY_TOKEN)
DUMMY_MSG_LEN = 64
classifier = None
udsSockFile = None
udsClientConnection = None
debug_set(False)

class ConnectionThread(Thread):
    def __init__(self, sock_file):
        Thread.__init__(self)
        #Check if socket already open
        try:
            os.unlink(sock_file)
        except OSError:
            if os.path.exists(sock_file):
                raise Exception("Address {} unavailable: someone already listening there?".format(sock_file))
        #Create and bind UDS socket for client requests
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  
        self.sock.bind(sock_file)
        
    def run(self):
        self.sock.listen(1)
        while True:
            #Wait for a connection
            connection, client_address = self.sock.accept() 
            #Read authentication token to allow connection
            try:
                data = connection.recv(len(DUMMY_TOKEN))
                print("Received client with token", data)
                #Verify token
                if data == DUMMY_TOKEN:
                    connection.sendall(DUMMY_TOKEN_CONF)
                    global udsClientConnection
                    udsClientConnection = connection
                else:
                    connection.close()     
            finally:
                pass
    
def reduceDim(arr, scale=0.1, offset=0):
    """inDim = len(arr)
    if inDim <= 2: return np.array(arr)
    x = 0
    y = 0
    dimRange = range(inDim)
    for i in dimRange[0::2]:
        x |= int(arr[i])<<i
    for i in dimRange[1::2]:
        y |= int(arr[i])<<i
    return [x,y]"""
    return arr

def classify(point, tag):
    global classifier
    if classifier == None:
        raise Exception("Classifier not initialized.")
    score = classifier.classify(reduceDim(point))
    if udsClientConnection != None:
        try:
            msg = "{}#{}#{}#".format(point, tag, score)
            udsClientConnection.sendall(msg.ljust(DUMMY_MSG_LEN))
        except Exception, msg:
            print("udsClientConnection -- Error", msg)    
    return score

def classifyWithLabel(point, tag):
    global classifier
    if classifier == None:
        raise Exception("Classifier not initialized.")
    return classifier.classifyWithLabel(point)

def train(enableSubscribe=True):
    """Initialize classifier. Returns 0 on success."""
    global classifier
    print("Started training.....")
    """Load training data set"""
    from dnssift.data.dns_tunneling import loader
    ds = loader.DataSet(MODEL_DATA_DIR)
    """Generate model ---
    Train with 'normal DNS' samles only"""
    if len(ds.training_samples) == 0:
        print("Training dataset empty.\n")
        return -1
    training_samples = [[reduceDim(x[0]), x[1]] for x in ds.training_samples]
    pos_samples = [[reduceDim(o[0]), o[1]] for o in ds.test_samples if o[1][1] == 'P']
    neg_samples = [[reduceDim(o[0]), o[1]] for o in ds.test_samples if o[1][1] == 'N']
    pos_training_samples = [training_samples[i] for i in random.sample(range(len(training_samples)), len(training_samples))]    
    startTime = time.time()
    k = 15#len(training_samples)/20
    classifier = Classifier(True)
    classifier.train(training_samples, k)
    endTime = time.time()
    pos_test = classifier.classify_many(pos_samples)
    neg_test = classifier.classify_many(neg_samples)
    pos_pred_error = len([p for p in pos_test if p == 'N'])
    neg_pred_error = len([p for p in neg_test if p == 'P'])
    print("DNSSIFT pos_error: {}% -- ({} / {})".format(round(100.0*pos_pred_error/len(pos_samples), 2),
                                                     pos_pred_error, len(pos_samples)))
    print("DNSSIFT neg_error: {}% -- ({} / {})".format(round(100.0*neg_pred_error/len(neg_samples), 2), 
                                                     neg_pred_error, len(neg_samples)))
    print("DNSSIF training time: {} seconds".format(endTime-startTime))    
    print("Finished training.....")
    if enableSubscribe:
        print("Initializing subscription socket.....")
        ct = ConnectionThread(UDS_FILE_NAME)
        ct.setDaemon(True)
        ct.start()
        print("Subscription socket created at {}.....".format(UDS_FILE_NAME))
    return 0
                
def randTest():
    import random
    from dnssift.data.dns_tunneling import loader
    ds = loader.DataSet()   
    test_data = [[reduceDim(x[0]), x[1]] for x in ds.test_samples]
    positive_samples = [sample for sample in test_data if sample[1][1] == 'P']
    negative_samples = [sample for sample in test_data if sample[1][1] == 'N']
    test_data = [positive_samples[i] for i in random.sample(range(len(positive_samples)), len(positive_samples))][:15]
    test_data.extend([negative_samples[i] for i in random.sample(range(len(negative_samples)), len(negative_samples))][:15])
    for item in test_data:
        print("(label: {}, classification: {}) -- source: {}".format(item[1][1], classifyWithLabel(item[0], item[1]), item[1][0]))
    return

def runMain():
    print("Running tests....")
    train()
    randTest() 
    print("Tests completed.")    
    return
if __name__ == "__main__":
    runMain()