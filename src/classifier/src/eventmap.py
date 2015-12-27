import numpy, vectorutils, time, sys, events, threading
import matplotlib.pyplot as plt
from cluster import *
from debug import *

def sigmoid(x):
    return 1 / (1 + numpy.exp(-x))

def reduceDim(arr, scale=0.1, offset=0):
    inDim = len(arr)
    x = 0.0
    y = 0.0
    for i in range(inDim/2):
        x += (i+1)*arr[i]
    for i in range(inDim/2, inDim):
        y += i*arr[i]
    return numpy.array([x,y])#offset+scale*numpy.array([sigmoid(x), sigmoid(y)])

def draw_circle(c,r, color):
    t = numpy.arange(0,1.01,.01)*2*numpy.pi
    x = r*numpy.cos(t) + c[0]
    y = r*numpy.sin(t) + c[1]
    plt.plot(x,y,color,linewidth=1)
      
color_marks = "bgrcmyk"
shape_marks = "^ov><*pshH+xd"

class EventPlotter(threading.Thread):
    def __init__(self, eventCtr, stopEvt, profileCluster):
        super(EventPlotter, self).__init__()
        self.profileCluster = profileCluster
        self.eventCtr = eventCtr
        self.stop_event = stopEvt
        self.new_nodes = []
 
    def run(self):
        plt.ion()
        centers = numpy.array([reduceDim(c) for c in self.profileCluster.centroids])
        for idx in range(len(centers)):
            color_mark = color_marks[idx%len(color_marks)]
            plt.plot(centers[idx][0], centers[idx][1], color_mark+'D')
        plt.show()
        plt.draw()
        points = numpy.array([reduceDim(numpy.zeros(6))])
        initSize = len(self.profileCluster.centroids)
        while not self.stop_event.is_set():
            new_nodes = self.eventCtr.collect()
            if len(new_nodes) > 0:
                new_nodes = numpy.array(new_nodes)
                out = self.profileCluster.cluster(new_nodes)
                #centers = numpy.array([reduceDim(self.profileCluster.centroids[idx]) for idx in out[0]])
                #points = numpy.concatenate((points, centers))  
                new_nodes = numpy.array([reduceDim(n) for n in new_nodes])
                for idx in range(len(new_nodes)):
                    if out[0][idx] < initSize:                
                        mark = 'k+'
                        #continue
                    else:
                        mark = color_marks[out[0][idx]%len(color_marks)] + '+'
                        plt.plot(new_nodes[idx][0], new_nodes[idx][1], mark)
                plt.draw()
                centers = self.profileCluster.getClusterNodes(reduceDim)
                print("CENTROIDS:", len(centers))
                for idx in range(len(centers)):
                    color_mark = color_marks[idx%len(color_marks)]
                    if idx < initSize:
                        color_mark = 'k'    
                    plt.plot(centers[idx][0], centers[idx][1], color_mark+'D')
                    #draw_circle((centers[idx][0], centers[idx][1]), centers[idx][2], color_mark)
                plt.draw()
                self.stop_event.wait(1)
                
class EventMap(events.EventCenter):
    def __init__(self, profile_path, *eventHandlers):
        super(EventMap, self).__init__(*eventHandlers)
        data  = numpy.load(profile_path)
        profile_data = data['arr_0']
        self.profile = Cluster(observations=profile_data, size=10, adaptive=True)
        self.stopEvent = threading.Event()
        self.plotter = EventPlotter(self, self.stopEvent, self.profile)
        self.plotter.start()
        
    def commit(self):
        self.stopEvent.set()
        self.plotter.join()

    
