from netevents import *
from fsevents import *
from procview import *
import threading, time, sys
       
class StdErrLogger(object):
    def __int__(self):
        self.outfile = open("/dev/null", "w+")
        
    def activate(self):
        sys.stderr = self
        
    def write(self, data):
        self.outfile.write(data)
        
    def writelines(self, data):
        self.outfile.writelines(data)
        
    def logToFile(self, filename):
        self.outfile = open(filename, "w+")
        
class Worker(threading.Thread):
    def __init__(self, stopEvt, eventCenter, *handlers):
        super(Worker, self).__init__()
        assert isinstance(eventCenter, EventCenter)
        for handler in handlers:
            assert isinstance(handler, BaseEventHandler)
        self.evtCenter = eventCenter
        self.handlers = [h for h in handlers]
        self.stop_event = stopEvt
            
    def run(self):
        while not self.stop_event.is_set():
            for handler in self.handlers:
                handler.pollEvents()
            self.stop_event.wait(2)
        for handler in self.handlers:
            handler.stop()   
        return     
            
class PollingWorker(Worker):
    def __init__(self, eventCenter, *handlers):
        super(PollingWorker, self).__init__(eventCenter, *handlers)
        
    def run(self): 
        turn = 0
        log_id = "events"+time.ctime()
        with open(self.evtCenter.getLogPath(), "w+") as log_file:
            events = []
            while not self.stop_event.is_set():
                for handler in self.handlers:
                    handler.pollEvents()
                self.stop_event.wait(2)
                turn += 1
                if turn % 6 == 0:
                    events.extend(self.evtCenter.collect())
                    numpy.savez(log_file, numpy.array([evt for evt in events]))
            for handler in self.handlers:
                handler.stop()
            self.evtCenter.collect()            
            log_file.close()
        return
            
if __name__ == '__main__':
    stderrLogger = StdErrLogger()
    fm = FSEventHandler()
    np = NetstatProcessor('-a','-t', '-e','-p', '-n')
    ps = ProcView(10, 100)
    eventCtr = EventCenter(np, fm, ps)
    stopEvent = threading.Event()
    def hh(f):
        f.add_path("/etc")
        #f.add_path("/home")
        f.add_path("/bin")
        f.add_path("/root")
    threading.Thread(target=hh, args=[fm]).start()    
    t = PollingWorker(stopEvent, eventCtr, ps, np)
    t2 = Worker(stopEvent, eventCtr, fm)
    try:
        stderrLogger.logToFile("../data/err.txt")
        stderrLogger.activate()
        t2.start()
        t.start()     
        sys.stdin.read()
    except KeyboardInterrupt:    
        stopEvent.set()
        eventCtr.commit()
        t.join()
        t2.join()
