import numpy, vectorutils, visjsadapter, time, sys, events, threading, random
import cherrypy, os, urllib, pickle
import matplotlib, six
from cluster import *
from netevents import *
from fsevents import *
from procview import *
from debug import *


NODES = 'nodes'
EDGES = 'edges'
ID = 'id'
LABEL = 'label'
X = 'x'
Y = 'y'
SIZE = 'size'
SOURCE = 'from'
TARGET = 'to'
COLOR = 'color'
TYPE = 'type'
TITLE = 'title'
GROUP = 'group'
SHAPE = 'shape'
LEVEL = 'level'

class Worker(threading.Thread):
    def __init__(self, eventCenter, *handlers):
        assert isinstance(eventCenter, EventCenter)
        for handler in handlers:
            assert isinstance(handler, BaseEventHandler)
        super(Worker, self).__init__()
        self.evtCenter = eventCenter
        self.handlers = [h for h in handlers]
            
    def run(self):
        while not self.evtCenter.stopEvent.is_set():
            for handler in self.handlers:
                handler.pollEvents()
            self.evtCenter.stopEvent.wait(1)
        for handler in self.handlers:
            handler.stop()   
        return   
    
class EventPlotter(threading.Thread):
    def __init__(self, eventCtr, stopEvt, profileCluster):
        super(EventPlotter, self).__init__()
        self.profileCluster = profileCluster
        self.eventCtr = eventCtr
        self.stop_event = stopEvt
        self.new_nodes = []
 
    def run(self):
        while not self.stop_event.is_set():
            new_nodes = self.eventCtr.collect()
            if len(new_nodes) > 0:
                new_nodes = numpy.array(new_nodes)
                self.profileCluster.cluster(new_nodes)
            self.stop_event.wait(1)
                
class ClusterViz(Cluster):
    def __init__(self, **kwargs):
        super(ClusterViz, self).__init__(**kwargs)
        self.graph = {}
        self.runIdx = 0
        self.initSize = len(self.clusterNodes)
        self.colors = list(six.iteritems(matplotlib.colors.cnames))
        self.reservedColor = self.colors[1]       
        self.colors.remove(self.reservedColor) 
        self.initialize_graph()
        with open("../data/clusterviz_new.dump", "wb") as dstf:
            pickle.dump(self, dstf)
            dstf.close()
        
    def getNodeColor(self, idx):
        if idx >= self.initSize:
            return self.reservedColor[1]
        else:
            return self.colors[idx % len(self.colors)]       
        
    def initialize_graph(self):
        self.graph = {NODES:[], EDGES:[], 'physics':'true', 'hierarchical':{'enabled':'true', 'direction':'LR'}}
        self.runIdx = 0
        for idx in range(len(self.clusterNodes)):
            node = {ID:'node{}'.format(idx), LABEL:self.clusterNodes[idx].label, SIZE:1,
                    X:self.clusterNodes[idx].x, Y:self.clusterNodes[idx].y,
                    COLOR: self.getNodeColor(idx)}
            self.graph[NODES].append(node)  
            
    def cluster(self, observations):
        self.runIdx += 1
        clusters, dist = super(ClusterViz, self).cluster(observations)
        nodeIdx = 0
        if len(self.graph.keys()) > 100:
            self.initialize_graph()
        for idx in range(len(self.clusterNodes)):
            self.clusterNodes[idx].color = self.getNodeColor(idx)
        for cluster in clusters:
            #if nodeIdx %5 != 0:continue
            self.clusterNodes[cluster].size += 1
            radiusX = random.randint(-10,10)
            radiusY = random.randint(-10,10)
            node = {ID:'node_c{}_{}'.format(self.runIdx, nodeIdx), 
                    LABEL:observations[nodeIdx][1], 
                    COLOR:self.clusterNodes[cluster].color,
                    GROUP:nodeIdx, LEVEL:1}
            edge = {ID:'e{}_{}'.format(self.runIdx, nodeIdx), 
                    SOURCE:self.graph[NODES][cluster][ID], 
                    TARGET:node[ID], COLOR:self.clusterNodes[cluster].color,
                    X:self.clusterNodes[cluster].x + radiusX,
                    Y:self.clusterNodes[cluster].y + radiusY,
                    TITLE:observations[nodeIdx][2] + str(observations[nodeIdx][0])}
            self.graph[NODES].append(node)
            #self.graph[EDGES].append(edge)
            nodeIdx +=1
        return clusters, dist
        
    def print_graph(self): 
        print(self.graph)
        
class EventMap(events.EventCenter):
    def __init__(self, profile_path, *eventHandlers):
        super(EventMap, self).__init__(*eventHandlers)
        data  = numpy.load(profile_path)
        profile_data = data['arr_0']
        with open("../data/clusterviz.dump", "rb") as srcf:
            self.profile = pickle.load(srcf)
            srcf.close()
        self.profile = ClusterViz(observations=profile_data, size=15, adaptive=True)
        self.stopEvent = threading.Event()
        self.plotter = EventPlotter(self, self.stopEvent, self.profile)
        self.plotter.start()
    
    def index(self, query=None):
            try:
                gnrtr = visjsadapter.WebPage()
            except Exception:
                pass
            print(len(self.profile.graph["nodes"]))
            return gnrtr.getWebPage(self.profile.graph)
    index.exposed = True    
        
    def commit(self):
        self.stopEvent.set()
        self.plotter.join()
        
if __name__ == '__main__':
    debug_set(False)
    fm = FSEventHandler()
    def hh(f):
        f.add_path("/etc")
        f.add_path("/home")
        f.add_path("/bin")
        f.add_path("/root")
    threading.Thread(target=hh, args=[fm]).start()
    np = NetstatProcessor('-a','-t', '-e','-p', '-n')
    ps = ProcView(10, 10)
    evtMap = EventMap("../data/test.ft", np)
    t = Worker(evtMap, np, ps)
    #t2 = Worker(evtMap, fm)
    try:
        #t2.start()
        t.start()    
        cherrypy.quickstart(evtMap, '/', '../config/service.conf')        
    except KeyboardInterrupt:    
        evtMap.commit()
        t.join()
        #t2.join()