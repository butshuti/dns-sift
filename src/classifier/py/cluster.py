import vectorutils, numpy, math, sys
from debug import *
from hcluster import hcluster, draw_dendrogram

PARAM_THRESHOLD = "threshold"
PARAM_SIZE = "size"
PARAM_OBS = "observations"
PARAM_ADAPTIVE = "adaptive"

def draw_tree(observations, filename):
    node = hcluster([o[0] for o in observations])
    draw_dendrogram(node, [o[1] for o in observations], filename)
    return filename

def reduceDim(arr, scale=0.1, offset=0):
    inDim = len(arr)
    x = 0.0
    y = 0.0
    for i in range(inDim/2):
        x += (i+1)*arr[i]
    for i in range(inDim/2, inDim):
        y += i*arr[i]
    return numpy.array([x,y])

class ClusterNode(object):
    def __init__(self, coords, size=1):
        self.x = coords[0]/100
        self.y = coords[1]/100
        self.size = size
        self.color = "#770"
        self.label = "({},{})".format(self.x, self.y)
        
    def grow(self, incr=1):
        self.size += incr
    
    def __repr__(self):
        return "{}::({},{})".format(self.size, self.x, self.y)
        
class Cluster(object):
    def __init__(self, **kwargs):
        if PARAM_OBS not in kwargs:
            raise Exception("Cluster initialization requires initial observations")
        elif (PARAM_SIZE not in kwargs) and (PARAM_THRESHOLD not in kwargs):
            raise Exception("Cluster initialization requires either an initial size or a distance threshold.")
        obs_raw = kwargs[PARAM_OBS]
        obs = numpy.array([arr[0] for arr in obs_raw])
        self.adaptive = False
        if PARAM_SIZE in kwargs:
            self.centroids, self.min_dist = vectorutils.kmeans(obs, kwargs[PARAM_SIZE])
        else:
            self.centroids, self.min_dist = vectorutils.kmeans(obs, math.ceil(len(obs)/3), kwargs[PARAM_THRESHOLD])
            self.adaptive = True
        self.max_radius = 1000
        trials, dist = self._cluster(obs_raw)
        self.max_radius = 2 * numpy.max(dist)
        self.clusterNodes = [ClusterNode(reduceDim(arr),0.001) for arr in self.centroids]
        if PARAM_ADAPTIVE in kwargs:
            self.adaptive = bool(kwargs[PARAM_ADAPTIVE])  
        for idx in range(len(self.clusterNodes)):
            self.clusterNodes[trials[idx]].label = 'group {}'.format(idx)
            
    def _cluster(self, observations):
        clusters, dist = vectorutils.vq(numpy.array([obs[0] for obs in observations]), self.centroids)
        if not self.adaptive:
            return clusters, dist
        outliers = {}
        offshoot_centers = set()
        for idx in range(len(dist)):
            if dist[idx] >= self.max_radius:
                outliers[idx] = observations[idx][0]
                offshoot_centers.add(clusters[idx])
        if len(outliers) > 0:
            offs = len(self.centroids)
            temp_offs = offs
            new_dist = numpy.inf
            new_obs = numpy.array(outliers.values())
            new_centroids, new_dist = vectorutils.thresholded_cluster(new_obs, self.max_radius)
            k = len(new_centroids)
            #debug_plot(new_centroids, 'rD')
            #debug_print(clusters, dist)
            debug_print("RADIUS {} EXCEEDED: creating {} new MAX{}-centers for {}".format(self.max_radius, k, new_dist, outliers))            
            self.centroids = numpy.resize(self.centroids, (offs+k, len(self.centroids[0])))
            for center in new_centroids:
                self.centroids.put(temp_offs, center)
                temp_offs += 1
            new_clusters, new_dist = vectorutils.vq(numpy.array(outliers.values()), new_centroids)
            #debug_print("NEW CENTERS")
            #debug_print(new_clusters, new_dist)
            old_cluster_idx = outliers.keys()
            for idx in range(len(new_dist)):
                clusters[old_cluster_idx[idx]] = new_clusters[idx]
                dist[old_cluster_idx[idx]] = new_dist[idx]
        return clusters, dist
    
    def cluster(self, observations):
        clusters, dist = self._cluster(observations)
        oldNum = len(self.clusterNodes)
        if oldNum != len(self.centroids):
            oldSizes = [cluster.size for cluster in self.clusterNodes]
            oldLabels = [cluster.label for cluster in self.clusterNodes]
            oldXs = [cluster.x for cluster in self.clusterNodes]
            oldYs = [cluster.y for cluster in self.clusterNodes]
            self.clusterNodes = [ClusterNode(reduceDim(arr),0.001) for arr in self.centroids]
            for idx in range(oldNum):
                self.clusterNodes[idx].size = oldSizes[idx]
                self.clusterNodes[idx].label = oldLabels[idx]
        for idx in range(len(clusters)):
            self.clusterNodes[clusters[idx]].size = max(self.clusterNodes[clusters[idx]].size, dist[idx])
            if idx >= oldNum and dist[idx] == 0:
                self.clusterNodes[clusters[idx]].label = observations[idx][1]
        return clusters, dist
    
    def draw_map(self, observations):
        return None
    
    def getClusterNodes(self, dimFunc):
        ret = [(0,0,0)]*len(self.clusterNodes)
        mapOverLay = (0,0)
        def newCoords(x, y, size):
            if x+size > mapOverLay[0] and y+size > mapOverLay[1]:
                return x,y
            mapOverLay[0] += size
            mapOverLay[1] += size
            return (mapOverlay[0], mapOverLay[1])
        for idx in range(len(ret)):
            coords = dimFunc(self.centroids[idx])
            coords = newCoords(coords[0], coords[1], self.clusterNodes[idx].size)
            ret[idx] = (coords[0], coords[1], self.clusterNodes[idx].size)
        return numpy.array(ret)
    
class HCluster(Cluster):
    def __init__(self, **kwargs):
        if PARAM_OBS not in kwargs:
            raise Exception("Cluster initialization requires initial observations")
        elif PARAM_THRESHOLD not in kwargs:
            raise Exception("Hierarchical cluster initialization requires a distance threshold.")
        obs_raw = kwargs[PARAM_OBS]
        obs = numpy.array([arr[0] for arr in obs_raw])
        self.adaptive = False
        self.min_dist = float(kwargs[PARAM_THRESHOLD])/3
        self.max_radius = float(kwargs[PARAM_THRESHOLD])
        tree = hcluster(obs)
        clusters = tree.extract_clusters(self.max_radius) 
        self.centroids = numpy.array([c.vec for c in clusters])
        #trials, dist = self._cluster(obs_raw)
        self.clusterNodes = [ClusterNode(reduceDim(arr),0.001) for arr in self.centroids]
        if PARAM_ADAPTIVE in kwargs:
            self.adaptive = bool(kwargs[PARAM_ADAPTIVE])  
        #for idx in range(len(self.clusterNodes)):
        #    self.clusterNodes[trials[idx]].label = 'group {}'.format(idx)    
        return
    def draw_map(self, observations):
        filename = '/home/hazirex/dump/session_prof/log.jpg'
        return draw_tree(observations, filename)