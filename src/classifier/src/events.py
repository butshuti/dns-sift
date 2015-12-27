import numpy, pprint, time

class BaseEvent(object):
    FEATURE_SIZE = 5
    def __init__(self, timestamp, eventCode, eventName, cummulative=False):
        self.eventTs = timestamp
        self.eventCode = eventCode
        self.eventName = eventName
        self.featureVector = numpy.zeros(BaseEvent.FEATURE_SIZE+1)
        self.featureVector.put(0, eventCode.__hash__()&0xff)
        self.cummulative = cummulative
        self.cause = "_un_"
        if self.cummulative < 0: raise ValueError("Cummulative flag must be a valid feature column index (>=1)")
        
    def updateFeature(self, idx, val):
        if idx >= BaseEvent.FEATURE_SIZE:
            raise ValueError("Index must be less than feature size.")
        self.featureVector.put(idx+1, val)
        return self
    
    def aggregate(self, other):
        assert isinstance(other, BaseEvent)
        if not self.cummulative: raise Exception("This event type does not aggreagate.")
        self.featureVector[self.cummulative] += other.featureVector[self.cummulative]
        return self
    
    def __repr__(self):
        
        return self.featureVector.__repr__() + "/" +self.eventCode + self.eventName
    
class LabeledEvent(BaseEvent):
    def __init__(self, timestamp, eventCode, eventName, label):
        super(LabeledEvent, self).__init__(timestamp, eventCode, eventName)
        self.cause = label
        
    '''def __repr__(self):
            return self.eventCode + self.eventName + "<" + self.cause + ">"  ''' 
        
class BaseEventHandler(object):
    def __init__(self):
        self.eventCenter = None
        
    def setEventCenter(self, evtCtr):
        if self.eventCenter:raise Exception("Cannot register more than one event center per handler.")
        else:self.eventCenter = evtCtr
        
    def registerEvent(self, evt):
        if self.eventCenter:self.eventCenter.notify(evt)
        else: raise Exception("No registered event center.")
        
    def pollEvents(self):
        raise Exception("Should be implemented by subclass")
    
    def stop(self):
        raise Exception("Should be implemented by subclass.")
    
        
class EventCenter(object):
    def __init__(self, *eventHandlers):
        self.events = {}
        self.num_events = 0
        self.handlers = []
        self.log_id = "events"+time.ctime()
        for evtH in eventHandlers:
            if isinstance(evtH, BaseEventHandler):
                evtH.setEventCenter(self)
                self.handlers.append(evtH)
            else:
                raise Exception("Object not an instance of BaseEventHandler.")
        
    def getLogPath(self, exiting=False):
        if exiting :
            return "../data/{}.ft".format(self.log_id)
        return "../data/{}_onExit.ft".format(self.log_id)
    
    def notify(self, evt):
        if isinstance(evt, BaseEvent):
            if evt.cummulative:
                key = evt.eventCode + evt.eventName
                if key in self.events:
                    #print(key, "FOUND. AGGREGATING.....", str(evt))
                    self.events[key] = self.events[key].aggregate(evt)
                else:
                    self.events[key] = evt
            else:
                self.events[self.num_events] = evt
        self.num_events += 1
        return
    
    def collectFeatures(self):
        ret = []
        if len(self.events):
            ret = [evt.featureVector for evt in self.events.values()]
        self.events = {}
        self.num_events = 0
        return ret
    
    def collect(self):
            ret = []
            if len(self.events):
                ret = [(evt.featureVector, evt.eventName, evt.cause) for evt in self.events.values()]
            self.events = {}
            self.num_events = 0
            return ret
    
    def commit(self):
        for handler in self.handlers:
            handler.stop()        
        with open(self.getLogPath(True), "w+") as log_file:
            events = self.collect()
            numpy.savez(log_file, numpy.array([evt for evt in events]))
            log_file.close()
        return