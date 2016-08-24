import math, random, numpy, copy
import debug

class Point(object):
    def __init__(self, point):
        self.point = point
        self.cluster = None
        
    def assignToCluster(self, cluster):
        self.cluster = cluster
	
    def __add__(self, other):
	return self.point + other.point
        
def whiten(data):
	std_dev = numpy.std(data, axis=0)
	return data / std_dev
	
	
def kmeans(data, k, threshold=0.00001, iterNum=20):
    if 1 == 1:
	return thresholded_cluster(data, infer_radius(data, k))
    if k > len(data): raise ValueError("Number of centers cannot be greater than number of observations.")
    centers, points = initCentroids(data, k)
    centers, points = cluster(numpy.array([p for p in points]), numpy.array([p for p in centers]))
    diff = numpy.inf
    cRound = 0
    old_centers = None
    points_r = numpy.array(points) 
    centers_r = numpy.array(centers)
    diff = threshold + 1
    prev_diff = diff
    distorsion = numpy.inf
    while diff > threshold and cRound < iterNum :
        cRound +=1
	old_centers = centers
        centers, points = cluster(points_r, centers_r)
	centers = updatedCenters(points, centers)
	prev_diff = distorsion
        distorsion = updatedVariance(points)
	diff = abs(distorsion - prev_diff)
    return (numpy.array([p.point for p in centers]), distorsion)

def infer_radius(data, k):
    center = numpy.mean(data, axis=0)
    diff = 0.
    for point in data:
	diff += numpy.sum((point - center)**2)
    variance = numpy.sqrt(diff)
    return variance / (k ** 2)
    
def thresholded_cluster(data, max_radius):
    points = data[:]
    centroids = {0:[points[0], [points[0]]]}
    max_radius = max_radius
    for idx in range(len(points)):
	found_fit = False
	for clusterPt in centroids:
	    if getDistance(points[idx], centroids[clusterPt][0]) < max_radius:
		found_fit = True
		centroids[clusterPt][1].append(points[idx])
		centroids[clusterPt][0] = numpy.mean(centroids[clusterPt][1], axis=0)
		break
	if not found_fit:
	    centroids[idx] = [points[idx], [points[idx]]]
    ret = [p[0] for p in centroids.values()]
    debug.debug_print("NEW CENTROIDS: {} from {} points".format(len(ret), len(points)), ret)
    return numpy.array(ret), max_radius
    
def vq(data, code_book):
    (n, d) = data.shape
    if numpy.ndim(data) != numpy.ndim(code_book):
	raise ValueError("Code book and input must have the same rank.")
    if d != code_book.shape[1]:
	raise ValueError("Input error: please check that observations have the same shape as the code_book")
    ret = numpy.zeros(n, dtype=int)
    minDist = numpy.zeros(n)
    for obsNdx in range(n):
        observation = data[obsNdx]
        minDist[obsNdx] = sum((observation - code_book[0])**2)
        for idx in range(1, len(code_book)):
            dist = sum((observation - code_book[idx])**2)
            if dist < minDist[obsNdx]:
                minDist[obsNdx] = dist
                ret[obsNdx] = idx
    return ret, numpy.sqrt(minDist)

def initCentroids(points, k):
    temp = random.sample(points,k)
    centers = [Point(p) for p in temp]
    points = [Point(p) for p in points]
    for i in range(len(points)):
        points[i].assignToCluster(centers[i * k/len(points)])
    return (centers, points)

def cluster(data, code_book):
    '''(n, d) = data.shape
    if numpy.ndim(data) != numpy.ndim(code_book):
	raise ValueError("Code book and input must have the same rank.")
    if d != code_book.shape[1]:
	raise ValueError("Input error: please check that observations have the same shape as the code_book")'''
    n = data.shape[0]
    minDist = numpy.zeros(n)
    for obsNdx in range(n):
        observation = data[obsNdx]
        minDist[obsNdx] = getPointDistance(observation, code_book[0])
        for idx in range(1, len(code_book)):
	    cb = code_book[idx]
            dist = getPointDistance(observation, code_book[idx])
            if dist < minDist[obsNdx]:
                minDist[obsNdx] = dist
		data[obsNdx].assignToCluster(code_book[idx])
    return (code_book, data)

def getPointDistance(p1, p2):
    return sum((p1.point - p2.point)**2)

def getDistance(p1, p2):
    return numpy.sqrt(sum((p1 - p2)**2))

def updatedVariance(points):
    diff = 0.0
    for p in points:
        if p.cluster != None:
            diff += numpy.sqrt(numpy.sum((p.point - p.cluster.point)**2, ))
    return numpy.sqrt(diff)/2

def updatedCenters(points, centers):
    for center in centers:
	center.point = normalizedCenter(center.point, [p.point for p in points if p.cluster == center])
    return centers

def normalizedCenter(orig, points):  
    if len(points) == 0:return orig
    point = numpy.mean(points, axis=0)
    return point
