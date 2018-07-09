from dnssift.py.classifier import *
from dnssift.py.debug import *
import dnssift.configutils as cfg
from threading import Thread
import os
import socket
import time
from pca import PCAProjection

cfgParams = cfg.parseConf()
UDS_FILE_NAME = cfgParams["uds_sock_file"]
MODEL_DATA_DIR = cfgParams["model_data_dir"]
DUMMY_TOKEN = "no_token"
DUMMY_TOKEN_CONF = "{}=>{}".format(DUMMY_TOKEN, DUMMY_TOKEN)
DUMMY_MSG_LEN = 64
udsSockFile = None
debug_set(False)


class ConnectionThread(Thread):
    def __init__(self, sock_file):
        Thread.__init__(self)
        # Check if socket already open
        try:
            os.unlink(sock_file)
        except OSError:
            if os.path.exists(sock_file):
                raise Exception("Address {} unavailable: someone already listening there?".format(sock_file))
        # Create and bind UDS socket for client requests
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  
        self.sock.bind(sock_file)
        self.udsClientConnection = None

    def get_uds_connection(self):
        return self.udsClientConnection

    def run(self):
        self.sock.listen(1)
        while True:
            # Wait for a connection
            connection, client_address = self.sock.accept() 
            # Read authentication token to allow connection
            try:
                data = connection.recv(len(DUMMY_TOKEN))
                print("Received client with token", data)
                # Verify token
                if data == DUMMY_TOKEN:
                    connection.sendall(DUMMY_TOKEN_CONF)
                    self.udsClientConnection = connection
                else:
                    connection.close()     
            finally:
                pass


class ClassifierInterface(object):
    def __init__(self, debug_label):
        self.classifier = None
        self.connection_thread = None
        self.debug_label = debug_label
        self.projection = None

    def pca(self, arr):
        if self.projection is not None:
            return list(self.projection.project(arr))
        return arr

    def reduce_dim(self, arr):
        r_arr = self.pca(arr)
        return arr[-10:]

    def classify(self, point, tag):
        if self.classifier is None:
            raise Exception("Classifier not initialized.")
        point = self.reduce_dim(point)
        score = self.get_score(point)
        if self.connection_thread is not None and self.connection_thread.get_uds_connection() is not None:
            try:
                msg = "{}#{}#{}#".format(point, tag, score)
                self.connection_thread.get_uds_connection().sendall(msg.ljust(DUMMY_MSG_LEN))
            except Exception, msg:
                print("Error", msg)
        return score

    def classify_many(self, arr):
        return self.classifier.classify_many(arr)

    def get_score(self, point):
        return self.classifier.classify(point)

    def classify_with_label(self, point, tag):
        if self.classifier is None:
            raise Exception("Classifier not initialized.")
        return self.classifier.classifyWithLabel(point)

    def train_classifier(self, training_samples):
        k = len(training_samples)/10
        self.classifier = Classifier(True)
        self.classifier.train(training_samples, k)
        return self.classifier

    def train(self, enable_subscribe=True):
        """Initialize classifier. Returns 0 on success."""
        print("{}: Started training.....".format(self.debug_label))
        """Load training data set"""
        from dnssift.data.dns_tunneling import loader
        ds = loader.DataSet(MODEL_DATA_DIR)
        data = list(ds.training_samples)
        data.extend(list(ds.test_samples))
        self.projection = PCAProjection([x[0] for x in data])
        """Generate model ---
        Train with 'normal DNS' samles only"""
        if len(ds.training_samples) == 0:
            print("Training dataset empty.\n")
            return -1
        training_samples = [[self.reduce_dim(x[0]), x[1]] for x in ds.training_samples]
        pos_samples = [[self.reduce_dim(o[0]), o[1]] for o in ds.test_samples if o[1][1] == 'P']
        neg_samples = [[self.reduce_dim(o[0]), o[1]] for o in ds.test_samples if o[1][1] == 'N']
        start_time = time.time()
        self.classifier = self.train_classifier(training_samples)
        end_time = time.time()
        pos_test = self.classify_many(pos_samples)
        neg_test = self.classify_many(neg_samples)
        pos_pred_error = len([p for p in pos_test if p != 'P'])
        neg_pred_error = len([p for p in neg_test if p == 'P'])
        tp = len(pos_test) - pos_pred_error
        tn = len(neg_test) - neg_pred_error
        fp = neg_pred_error
        pos_recall = float(tp) / len(pos_test)
        neg_recall = float(tn) / len(neg_test)
        recall = 0.5 * (pos_recall + neg_recall)
        print("DNS:     error: {}% -- ({} / {}); recall: {:.5f}".format(round(100.0*pos_pred_error/len(pos_samples), 2),
                                                           pos_pred_error, len(pos_samples), pos_recall))
        print("non-DNS: error: {}% -- ({} / {}); recall: {:.5f}".format(round(100.0*neg_pred_error/len(neg_samples), 2),
                                                           neg_pred_error, len(neg_samples), neg_recall))
        print("Overall: error: {}% -- ({} / {}); recall: {:.5f}".format(round(100.0*(neg_pred_error+pos_pred_error)/(len(neg_samples) + len(pos_samples)), 2),
                                                           neg_pred_error+pos_pred_error, len(neg_samples)+ len(pos_samples), recall))
        print("training time: {} seconds".format(end_time-start_time))
        print("{}: Finished training.....".format(self.debug_label))
        if enable_subscribe:
            print("Initializing subscription socket.....")
            self.connection_thread = ConnectionThread(UDS_FILE_NAME)
            self.connection_thread.setDaemon(True)
            self.connection_thread.start()
            print("Subscription socket created at {}.....".format(UDS_FILE_NAME))
        return 0

    def rand_test(self):
        import random
        from dnssift.data.dns_tunneling import loader
        ds = loader.DataSet(MODEL_DATA_DIR)
        test_data = [[self.reduce_dim(x[0]), x[1]] for x in ds.test_samples]
        positive_samples = [sample for sample in test_data if sample[1][1] == 'P']
        negative_samples = [sample for sample in test_data if sample[1][1] == 'N']
        test_data = [positive_samples[i] for i in random.sample(range(len(positive_samples)), len(positive_samples))][:15]
        test_data.extend([negative_samples[i] for i in random.sample(range(len(negative_samples)), len(negative_samples))][:15])
        for item in test_data:
            print("(label: {}, classification: {}) -- source: {}".format(item[1][1], self.classify_with_label(item[0], item[1]), item[1][0]))
        return

    def run_main(self, enable_subscribe=True):
        print("Running tests....")
        self.train(enable_subscribe)
        self.rand_test()
        print("Tests completed.")
        return


if __name__ == "__main__":
    ClassifierInterface("DNSSift_clusters").run_main(False)
