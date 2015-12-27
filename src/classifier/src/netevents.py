import pynetstat, os, time
from events import *

pynetstat.NONBLOCKING_MODE = True
POLL_INTERVAL = 2


NET_EVENT_CODE = "net"

NET_IFACES_FEATURE_POS = 0
NET_SOCKETS_FEATURE_POS = 1
NET_BIND_FEATURE_POS = 2
NET_CONN_FEATURE_POS = 3
NET_DATA_FEATURE_POS = 4

NET_RHOST_REGULAR = 2
NET_RHOST_LOCAL = 0
NET_RHOST_NEW = 5
NET_RHOST_PERSISTENT = 6

def getRemoteHistory(rHost):
    return NET_RHOST_REGULAR

class NetstatProcessor(pynetstat.netstat, BaseEventHandler):
    def __init__(self, *options):
        BaseEventHandler.__init__(self)
        pynetstat.netstat.__init__(self, *options)   
        self.cmdoptions.append('-n')
        
    def update(self):
        super(NetstatProcessor, self).update()
        if len(self.inet_connections) and self.eventCenter:
            ts = time.time()
            for t in self.inet_connections:
                localPort = int(getattr(t, "LocalPort"))
                remotePort = getattr(t, "ForeignPort")
                state = getattr(t, "State")
                if remotePort == '*':
                    remotePort = 0
                else:
                    remotePort = int(remotePort)
                pendingData = float(getattr(t, "RecvQ")) + float(getattr(t, "SendQ"))
                rHost = getattr(t, "ForeignAddress")
                rHostReputation = getRemoteHistory(rHost)
                self.registerEvent(BaseEvent(ts, NET_EVENT_CODE + state, "L{}{}".format(getattr(t, "User"), localPort)).updateFeature(NET_BIND_FEATURE_POS, localPort))
                self.registerEvent(BaseEvent(ts, NET_EVENT_CODE + state, "L{}{}".format(getattr(t, "User"), 
                                                                                getattr(t, "Program")), NET_BIND_FEATURE_POS).updateFeature(NET_BIND_FEATURE_POS, localPort))
                self.registerEvent(BaseEvent(ts, NET_EVENT_CODE + state, "LQ{}{}".format(getattr(t, "RecvQ"), 
                                                                                         getattr(t, "SendQ"))).updateFeature(NET_DATA_FEATURE_POS, pendingData))
                self.registerEvent(BaseEvent(ts, NET_EVENT_CODE, "R{}{}".format(localPort, rHost), NET_CONN_FEATURE_POS).updateFeature(NET_CONN_FEATURE_POS, rHostReputation))  
                self.registerEvent(BaseEvent(ts, NET_EVENT_CODE, "R{}{}".format(getattr(t, "Proto"), remotePort), NET_CONN_FEATURE_POS).updateFeature(NET_CONN_FEATURE_POS, rHostReputation))
                self.registerEvent(BaseEvent(ts, NET_EVENT_CODE, "S{}".format(getattr(t, "Proto")), NET_SOCKETS_FEATURE_POS).updateFeature(NET_SOCKETS_FEATURE_POS, 1))
        return
    
    def pollEvents(self):
        self.update()
        
    def stop(self):
        pass