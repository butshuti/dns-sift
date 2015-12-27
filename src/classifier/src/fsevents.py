import threading, pyinotify, events
from time import time
from events import *

FS_EVENT_CODE = "fs"
FS_ACCESS_CODE = "fsACC"
FS_MODIF_CODE = "fsMOD"
FS_CREAT_CODE = "fsCREAT"
FS_DEL_CODE = "fsDEL"
FS_OPEN_CODE = "fsOPEN"
FS_PRIV_MODIF_CODE = "fsPRVMOD"

#Watched directories
FS_DEV = "dev"
FS_ETC = "etc"
FS_ROOT = "root"
FS_HOME = "home"
FS_LIB = "lib"
FS_USR = "usr"
FS_BIN = "bin"

#Action types
ACTION_READ = 1
ACTION_WRITE = 2
ACTION_CREATE = 3
ACTION_MODIFY = 4
ACTION_DELETE = 5
ACTION_LOCK = 6

#Read events
FS_READ_FEATURE_POS = 2
FS_READ_NORMAL = 1
FS_READ_CONFIG = 2
FS_READ_DEV = 5
#Write events
FS_WRITE_FEATURE_POS = 1
FS_WRITE_NORMAL = 1
FS_WRITE_NEW_NORMAL = 2
FS_WRITE_NEW_PRIV = 10
FS_WRITE_CONFIG = 6
FS_WRITE_BIN_LIB = 8
FS_WRITE_DEV = 3
FS_WRITE_ROOT = 15
#Denial events
FS_DENY_MUCH_WRITTEN = 5
FS_DENY_HIGH_FREQ_ACCESS = 3
FS_DENY_UNAVAIL = 10

FS_CUMULATIVE_FIELD_IDX = 4

def getSensitivityByFileName(path, action):
    part = path.split("/")[1]
    if action == ACTION_READ:
        if part == FS_DEV: return FS_READ_DEV
        elif part == FS_ETC: return FS_READ_CONFIG
        else: return FS_READ_NORMAL
    elif action == ACTION_WRITE or action == ACTION_MODIFY:
        if path == FS_DEV: return FS_WRITE_DEV
        elif path == FS_ROOT: return FS_WRITE_ROOT
        elif path == FS_BIN or path == FS_LIB: return FS_WRITE_BIN_LIB
        elif path == FS_ETC: return FS_WRITE_CONFIG
        else: return FS_WRITE_NORMAL
    elif action == ACTION_CREATE or action == ACTION_DELETE:
        if path == FS_ROOT or path == FS_BIN or path == FS_LIB: return FS_WRITE_NEW_PRIV
        else: return FS_WRITE_NEW_NORMAL
    raise Exception("Unknown operation class.")

sensitivity_levels = []

class FSEvent(BaseEvent):
    def __init__(self, timestamp, eventCode, eventName, cummulative=False):
        super(FSEvent, self).__init__(timestamp, eventCode, eventName, FS_CUMULATIVE_FIELD_IDX)
        
class FSEventHandler(pyinotify.ProcessEvent, BaseEventHandler):
    SENSITIVITY_NORMAL = "usr"  #for user files
    SENSITIVITY_PRVLG = "prvlg" #for protected/privileged files
    SENSITIVITY_SYSTEM = "sys" #system or config files
    SENSITIVITY_LOG = "log" #log files
    
    def my_init(self):
        events.BaseEventHandler.__init__(self)
        self.watch_manager = pyinotify.WatchManager()
        self.notifier = pyinotify.Notifier(self.watch_manager, self)
        self.eventCode = FS_EVENT_CODE
        self.started = False
        
            
    def add_path(self, path):
        self.watch_manager.add_watch(path, pyinotify.ALL_EVENTS, rec=True)
        
    def process_IN_ACCESS(self, event): 
        ft_val = getSensitivityByFileName(event.pathname, ACTION_READ)
        evt = FSEvent(time.time(), self.eventCode, "ACC:"+event.pathname)
        evt.updateFeature(FS_READ_FEATURE_POS, ft_val)
        self.registerEvent(evt)
    
    def process_IN_ATTRIB(self, event):
        ft_val = getSensitivityByFileName(event.pathname, ACTION_MODIFY)
        evt = FSEvent(time.time(), self.eventCode, "ATT:"+event.pathname)
        evt.updateFeature(FS_WRITE_FEATURE_POS, ft_val)
        self.registerEvent(evt)        
    
    def process_IN_CLOSE_WRITE(self, event):
        ft_val = getSensitivityByFileName(event.pathname, ACTION_WRITE)
        evt = FSEvent(time.time(), self.eventCode, "WRT:"+event.pathname)
        evt.updateFeature(FS_WRITE_FEATURE_POS, ft_val)
        self.registerEvent(evt)        
    
    def process_IN_CREATE(self, event):
        ft_val = getSensitivityByFileName(event.pathname, ACTION_CREATE)
        evt = FSEvent(time.time(), self.eventCode, "NEW:"+event.pathname)
        evt.updateFeature(FS_WRITE_FEATURE_POS, ft_val)
        self.registerEvent(evt)        
    
    def process_IN_DELETE(self, event):
        ft_val = getSensitivityByFileName(event.pathname, ACTION_DELETE)
        evt = FSEvent(time.time(), self.eventCode, "DEL:"+event.pathname)
        evt.updateFeature(FS_DENY_FEATURE_POS, ft_val)
        self.registerEvent(evt)        
    
    def process_IN_MODIFY(self, event):
        ft_val = getSensitivityByFileName(event.pathname, ACTION_MODIFY)
        evt = FSEvent(time.time(), self.eventCode, "CHG:"+event.pathname)
        evt.updateFeature(FS_WRITE_FEATURE_POS, ft_val)
        self.registerEvent(evt)        
    
    def process_IN_OPEN(self, event):
        ft_val = getSensitivityByFileName(event.pathname, ACTION_READ)
        evt = FSEvent(time.time(), self.eventCode, "OPN:"+event.pathname)
        evt.updateFeature(FS_READ_FEATURE_POS, ft_val)
        self.registerEvent(evt)        
    
    def start(self):
        self.started = True
        self.notifier.loop()
        
    def stop(self):
        self.notifier.stop()
        self.started = False
        
    def pollEvents(self):
        if self.started:pass
        else:self.start()