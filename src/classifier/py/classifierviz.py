import numpy, time, sys, threading, random
import cherrypy, os, urllib, pickle
import matplotlib, six
from dnssift.py.cluster import *
from dnssift.py.debug import *
from os.path import expanduser
import sys, socket, struct
import dnssift.configutils as cfg
from  dnssift.py import vectorutils, visjsadapter


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
PROFILE_VIZ_DUMP = '/tmp/dnssift'
cfgParams = cfg.parseConf()
UDS_FILE_NAME = cfgParams["uds_sock_file"]
DUMMY_TOKEN = "no_token"
DUMMY_TOKEN_CONF = "{}=>{}".format(DUMMY_TOKEN, DUMMY_TOKEN)
DUMMY_MSG_LEN = 64  

            
class UDSEventsClient(threading.Thread):
    def __init__(self, udsPath, evtMap):
        super(UDSEventsClient, self).__init__()
        self.server_address = udsPath
        self.sock = self.connect()
        self.evtMap = evtMap
        
    def connect(self):
        #Create a UDS socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        #Connect the socket to the listening server
        print("Connecting to UDS server at {}".format(self.server_address))
        try:
            sock.connect(self.server_address)
            sock.sendall(DUMMY_TOKEN)
            reply = sock.recv(len(DUMMY_TOKEN_CONF))
            print("Server confirmation", reply)
        except socket.error, msg:
            print("Error", msg)
            sys.exit(1)
        return sock
    def run(self):
        while os.path.exists(self.server_address):
            data = self.sock.recv(255)
            toks = data.split("#")
            if len(toks) < 4:
                continue
            tags = toks[1].split(";")
            if len(tags[1]) < 2: continue
            qname = tags[1][::-1]
            score = toks[2]
            ip = socket.inet_ntoa(struct.pack("!I", eval(tags[0])))
            self.evtMap.update(eval(toks[0]), "{}@{}".format(qname, ip), score)
            
class ClusterViz(Cluster):
    def __init__(self, **kwargs):
        super(ClusterViz, self).__init__(**kwargs)
        self.graph = {}
        self.runIdx = 0
        self.initSize = len(self.clusterNodes)
        colors = matplotlib.colors.cnames
        colors.pop('indigo', None)
        colors.pop('darkgreen', None)
        self.colors = list(six.iteritems(colors))
        self.reservedColor = self.colors[1]       
        self.colors.remove(self.reservedColor) 
        self.initialize_graph()
        with open(PROFILE_VIZ_DUMP + "/clusterviz_new.dump", "wb") as dstf:
            pickle.dump(self, dstf)
            dstf.close()
        
    def getNodeColor(self, idx):
        if idx >= self.initSize:
            return self.reservedColor[1]
        else:
            return self.colors[idx % len(self.colors)]       
        
    def initialize_graph(self):
        self.graph = {NODES:[], EDGES:[], 'physics': {'repulsion': { 'springConstant': 0.31, 'nodeDistance': 220, 'damping': 0.41  }, 'minVelocity': 0.2,  'solver': 'repulsion' }, 'hierarchical':{'enabled':'true', 'direction':'LR'}}
        self.runIdx = 0
        for idx in range(len(self.clusterNodes)):
            node = {ID:'node{}'.format(idx), LABEL:self.clusterNodes[idx].label, SIZE:1,
                    X:self.clusterNodes[idx].x, Y:self.clusterNodes[idx].y,
                    COLOR: self.getNodeColor(idx)}
            self.graph[NODES].append(node)  
            
    def cluster(self, observations, tag):
        self.runIdx += 1
        clusters, dist = super(ClusterViz, self).cluster(observations)
        nodeIdx = 0
        if str(tag[1]) == '0':
            tagColor = 'red'
        else:
            tagColor = 'green'
        if len(self.graph.keys()) > 100:
            pass#self.initialize_graph()
        for idx in range(len(self.clusterNodes)):
            self.clusterNodes[idx].color = self.getNodeColor(idx)
        for cluster in clusters:
            #if nodeIdx %5 != 0:continue
            self.clusterNodes[cluster].size += 1
            radiusX = random.randint(-10,10)
            radiusY = random.randint(-10,10)
            node = {ID:'node_c{}_{}'.format(self.runIdx, nodeIdx), 
                                LABEL:tag[0],#observations[nodeIdx][1], 
                                TITLE:tag[0],
                                COLOR:tagColor,#self.clusterNodes[cluster].color,
                                GROUP:nodeIdx}
            edge = {ID:'e{}_{}'.format(self.runIdx, nodeIdx), 
                    SOURCE:self.graph[NODES][cluster][ID], 
                    TARGET:node[ID],
                    X:self.clusterNodes[cluster].x + radiusX,
                    Y:self.clusterNodes[cluster].y + radiusY}
            self.graph[NODES].append(node)
            self.graph[EDGES].append(edge)
            nodeIdx +=1
        return clusters, dist
        
    def print_graph(self): 
        print(self.graph)
        
class EventMap(object):
    def __init__(self):
        """Load training data set""" 
        from dnssift.data.dns_tunneling import loader
        ds = loader.DataSet()
        """Generate model"""
        training_samples = ds.training_samples
        self.profile = ClusterViz(observations=training_samples, size=5, threshold=1, adaptive=True)
        self.observations = set()
        self.logFile = open("{}/dnssift.log".format(PROFILE_VIZ_DUMP), "w+")

    def update(self, point, tag, label):
        self.profile.cluster(numpy.array([[point]]), (tag, label))
        self.observations.add(str([point,tag]))
        try:
            self.logFile.write("{},({}),{}\n".format(point, tag, label))
        except Exception:
            pass
        return
    
    def index(self, query=None):
            try:
                gnrtr = visjsadapter.WebPage()
                self.logFile.flush()
            except Exception:
                pass
            #if len(self.observations) > 5:
                #draw_tree(numpy.array([eval(l) for l in self.observations]), "/home/hazirex/dump/session_prof/dns.jpg")
            return gnrtr.getWebPage(self.profile.graph)
    index.exposed = True    
        
        
if __name__ == '__main__':
    import dnssift.configutils as cfg
    configs = cfg.parseConf()
    with open(configs["reporter_daemon_pidfile"], "w") as pidfile:
        pidfile.write(str(os.getpid()))
        pidfile.close()    
    debug_set(False)
    evtMap = EventMap()
    udsDataCollector = UDSEventsClient(UDS_FILE_NAME, evtMap)
    try:
        udsDataCollector.start()
        cherrypy.quickstart(evtMap, '/', '/etc/@package_name@conf/cherrypy.conf')        
    except KeyboardInterrupt:    
        evtMap.commit()
        udsDataCollector.join()
        sys.exit(1)
