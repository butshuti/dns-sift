import matplotlib.pyplot as plt
import matplotlib.mlab as mlab
import math
import dnssift.configutils as cfg
import numpy as np

cfgParams = cfg.parseConf()
MODEL_DATA_DIR = cfgParams["model_data_dir"]

POLAR = False
globalMeans = None
globalMaxes = None


def feature_cart_map(num, idx, dim, polar=False):
    section__w = math.radians(360.0)/dim
    angle = section__w*idx
    num = int(num)
    f_uniqueness = num & 0x07
    f_range = num >> 3
    f_code = num >> 5
    radius = (1+f_range) * (1+f_code) * 10
    angle += (f_code+1)*(section__w/4.0)
    angle -= (f_uniqueness+1)*(section__w/10.0)
    if not polar:
        x = radius * math.cos(angle)
        y = radius * math.sin(angle)        
        return x, y
    return angle, radius


def feature_vec_cart_map(arr, polar=False):
    dim = len(arr)
    points = []
    for idx in range(dim):
        points.append(feature_cart_map(arr[idx], idx, dim, polar))
    if globalMaxes is None:
        return points
    return np.maximum(np.array(points), 5*(points/(0.01+globalMaxes)))


def reduce_dim(points, polar=False):
    global globalMeans
    if globalMeans is None:
        raise Exception("Dimension pivots not initialized!")
    points = points - globalMeans
    points = np.round(points)
    ret = [0, 0]
    for point in points:
        ret[0] += point[0]**2
        ret[1] += point[1]**2
    return math.sqrt(ret[0]), 100+math.sqrt(ret[1])


def initialize_global_means(data_set):
    global globalMeans, globalMaxes
    globalMeans = np.average(data_set, axis=0)
    globalMaxes = np.absolute(np.amax(data_set, axis=0))
    return


def isValid(x):
    global globalMeans
    if globalMeans is None: return True
    return np.array(x).shape[0] == globalMeans.shape[0]


def model_viz(path, is_model_dir=False):
    """Load training data set"""
    from dnssift.data.dns_tunneling import loader
    ds = loader.DataSet(MODEL_DATA_DIR)
    if len(ds.training_samples) == 0:
        raise Exception("Training data set empty.\n")
    training_samples_view = [feature_vec_cart_map(x[0], POLAR) for x in ds.training_samples]
    initialize_global_means(training_samples_view)
    training_samples_view = [feature_vec_cart_map(x[0], POLAR) for x in ds.training_samples if isValid(x[0])]
    test_samples_view = [feature_vec_cart_map(x[0], POLAR) for x in ds.test_samples if isValid(x[0])]
    xs = []
    ys = []
    test_xs = []
    test_ys = []
    for point in training_samples_view:
        xs.extend([p[0] for p in point])
        ys.extend([p[1] for p in point])
    for point in test_samples_view:
        test_xs.extend([p[0] for p in point])
        test_ys.extend([p[1] for p in point])      
    plt.figure(2)
    plt.subplot(111, polar=POLAR)
    plt.scatter(xs, ys, s=600, zorder=11, c='g', edgecolors='g') 
    plt.plot(xs, ys, c='g', zorder=10, linewidth=5.0)
    plt.scatter(test_xs, test_ys, zorder=21, s=100, c='r', edgecolors='r', marker='H') 
    plt.plot(test_xs, test_ys, zorder=20, c='r', linestyle='dotted')
    if path is None:
        return
    if is_model_dir:
        viz_data = ds.loadDsDir(path, 'VIZ')
    else:
        viz_data = ds.loadDs(path, 'VIZ')
    viz_data = [feature_vec_cart_map(x[0], POLAR) for x in viz_data]
    viz_data_xs = []
    viz_data_ys = []
    for point in viz_data[:]:
        viz_data_xs.extend([p[0] for p in point])
        viz_data_ys.extend([p[1] for p in point])    
    plt.scatter(viz_data_xs, viz_data_ys, zorder=31, s=500, c='b', edgecolors='b', marker='*')
    plt.plot(viz_data_xs, viz_data_ys, zorder=30, c='b', linestyle='dotted')
    plt.show()
    return


if __name__ == '__main__':
    model_viz("/tmp/dnssift/datapoints.csv")
