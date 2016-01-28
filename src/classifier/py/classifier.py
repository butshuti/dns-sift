from cluster import *

class Classifier():
    def __init__(self):
        self.profile = None
        self.initSize = 0
        
    def train(self, data, k):    
        self.profile = Cluster(observations=data, size=k, adaptive=False)
        self.initSize = len(self.profile.centroids)
        
    def classify_many(self, observations):
        if self.profile == None:
            raise Exception("Classifier must be trained before testing.")
        out = self.profile.cluster(observations[:])    
        def is_conformant(x):
            if x < self.profile.max_radius:
                return 'P'
            else: return 'N'
        ret = [is_conformant(x) for x in out[1]]
        return ret 
    
    def classify(self, point):
        if self.classify_many(numpy.array([[point]]))[0] == 'P':
            return 1
        return 0