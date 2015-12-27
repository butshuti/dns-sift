from src.classifier import *
from src.debug import *

classifier = None
debug_set(False)

def classify(point):
    global classifier
    if classifier == None:
        raise Exception("Classifier not initialized.")
    return classifier.classify(point)

def train():
    global classifier
    """Load training data set"""
    from test_data.dns_tunneling import loader
    ds = loader.DataSet()
    """Generate model"""
    training_samples = ds.training_samples
    observations = ds.test_samples
    k = len(training_samples)/20
    classifier = Classifier()
    classifier.train(training_samples, k)
    return 0

if __name__ == "__main__":
    print("Running tests....")
    train()
    print("DNS 1", classify([0, 1, 1, 81, 1, 1, 1]))
    print("DNS 2", classify([0, 3, 3, 3, 3, 3, 3]))
    print("DNS 3", classify([1, 3, 3, 3, 3, 3, 3]))
    print("DNS 4", classify([128, 3, 3, 3, 3, 3, 3]))
    print("DNS 5", classify([64, 3, 3, 3, 3, 3, 3]))
    print("DNS 6", classify([128, 3, 3, 3, 3, 3, 3])) 
    
    print("NOT DNS 1", classify([48, 0, 0, 0, 40, 64, 0]))
    print("NOT DNS 2", classify([32, 0, 0, 0, 40, 64, 32]))
    print("NOT DNS 3", classify([32, 0, 0, 0, 40, 64, 0]))
    print("NOT DNS 4", classify([32, 0, 0, 0, 40, 64, 32]))
    print("NOT DNS 5", classify([32, 0, 0, 0, 40, 64, 32]))
    print("NOT DNS 6", classify([32, 0, 0, 0, 40, 64, 32]))
    print("NOT DNS 7", classify([32, 0, 0, 0, 40, 64, 0])) 
    print("Tests completed.")  
    
