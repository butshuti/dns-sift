from netevents import *
from fsevents import *
from procview import *
from eventmap import *

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
        
debug_set(False)
fm = FSEventHandler()
np = NetstatProcessor('-a','-t', '-e','-p', '-n')
ps = ProcView(10, 50)
evtMap = EventMap("../data/test.ft", np, fm, ps)
t = Worker(evtMap, ps, np)
t2 = Worker(evtMap, fm)
try:
    t2.start()
    t.start()     
    sys.stdin.read()
except KeyboardInterrupt:    
    evtMap.commit()
    t.join()
    t2.join()    