from Tkinter import *
import tkMessageBox, ttk
import dnssift.configutils as cfg
import os, time, threading, math
from subprocess import Popen, PIPE, call

CMD_LOG_FILE = "/tmp/dnssift_last_cmd_error.log"

class App:
  def __init__(self, window):
    self.window = window
    self.mainDaemonAlive = False
    self.reportServerAlive = False
    self.reportServerBut = None
    self.progressbarRunning = False
    self.nsListStr = StringVar(self.window)
    self.filterStatusStr = StringVar(self.window)
    self.reportClientStatusStr = StringVar(self.window)
    self.filterControlButStr = StringVar(self.window, "START")
    self.reportClientControlButStr = StringVar(self.window, "START")
    self.progressFrame = Frame(self.window, width=600, height=20)
    self.progressFrame.pack(side=TOP)
    Frame(self.window,width=600,height=10).pack(side=TOP)
    self.parseNS("/etc/resolv.conf")
    self.getDaemonStatus()
    self.home()
    Frame(self.window,width=600,height=10).pack(side=TOP)
    self.window.resizable(width=False, height=False)
    
  def home(self):
    """
    Initialize main window.
    """
    #Configured NS info frame
    nsFrame = Frame(self.window, relief="groove", borderwidth=1)
    Label(nsFrame, text="Configured nameservers:", height=2, anchor='w').grid(row=0, sticky="nsew")
    Label(nsFrame, textvariable=self.nsListStr, relief="sunken").grid(row=1, sticky="nsew")
    nsFrame.pack(side=TOP, fill=X, padx=20, pady=10, ipadx=20, ipady=5)
    ttk.Separator(self.window, orient="horizontal").pack(side=TOP, padx=20, fill=X)
    #filter daemon status frame
    statusFrame = Frame(self.window)
    Label(statusFrame, text="DNS filter status:", height=2, anchor='w').grid(row=0, column=0)
    Label(statusFrame, textvariable=self.filterStatusStr).grid(row=0, column=1)
    Button(statusFrame, textvariable=self.filterControlButStr, command=self.changeFilterStatus).grid(row=1, column=0, sticky=W)
    statusFrame.pack(side=TOP, fill=X, padx=20, pady=10, ipadx=20, ipady=5)
    ttk.Separator(self.window, orient="horizontal").pack(side=TOP, padx=20, fill=X)
    #web report client frame
    reportClientFrame = Frame(self.window)
    Label(reportClientFrame, text="Realtime report client status:", height=2, anchor='w').grid(row=0, column=0)
    Label(reportClientFrame, textvariable=self.reportClientStatusStr).grid(row=0, column=1)
    self.reportServerBut = Button(reportClientFrame, textvariable=self.reportClientControlButStr, command=self.changeReportClientStatus,
           state=self.getButtonStateForBool(self.mainDaemonAlive))
    self.reportServerBut.grid(row=1, column=0, sticky=W)
    reportClientFrame.pack(side=TOP, fill=X, padx=20, pady=10, ipadx=20, ipady=5)
    ttk.Separator(self.window, orient="horizontal").pack(side=TOP, padx=20, fill=X)
    return
    
  def getButtonStateForBool(self, boolVar):
    if boolVar : return NORMAL
    return DISABLED
  
  def shellCmd(self, cmdStr, successMsgStr, callback, background):
    """
    Run shell commmand and display final status in a message box.
    """
    if not background:
      p = Popen(cmdStr, stdout=PIPE, stderr=PIPE, shell=True, close_fds=True)
      output, err = p.communicate()
      returncode = p.returncode
    else:
      returncode = call("nohup {} &".format(cmdStr), shell=True)
    def resultCb(result):
      if result:
        tkMessageBox.showinfo("Success", successMsgStr)
      else:
        err = self.readErrLog(CMD_LOG_FILE)
        if len(err) < 10:
          err = "Operation failed. (return_code={}).".format(returncode)
        tkMessageBox.showerror("Error", err)         
    self.queryFunc(callback, resultCb)
    return
  
  def changeFilterStatus(self):
    """
    Start or stop the main engine.
    Action to take depends on the current state: (running=>STOP_current, nont_running=>START_new).
    """
    configs = cfg.parseConf()
    pidfile = configs['filter_daemon_pidfile']
    mainDaemonPID = self.readPIDFile(pidfile)    
    runInBackground = True
    if self.isProcAlive(mainDaemonPID):
      #Action is to kill a running dnssift.start
      cmdStr = "kill -USR1 {}".format(mainDaemonPID)
      runInBackground = False
      okMsg = "Filter daemon terminated."
      callback = lambda : not self.getDaemonStatus()[0]
    else:
      #dnssift.start
      cmdStr = "python -m dnssift.start 2> {} 1> /dev/null".format(CMD_LOG_FILE)
      okMsg = "Filter engine successfully started!"
      callback = lambda : self.getDaemonStatus()[0]
    self.shellCmd(cmdStr, okMsg, callback, runInBackground)
    self.getDaemonStatus()
  
  def changeReportClientStatus(self):
    """
    Start or stop the interface to event reporting
    Action to take depends on the current state: (running=>STOP_current, nont_running=>START_new).
    """
    configs = cfg.parseConf()
    pidfile = configs['reporter_daemon_pidfile']
    reportDaemonPID = self.readPIDFile(pidfile) 
    runInBackground = True
    if self.isProcAlive(reportDaemonPID):
      #Action is to kill a running dnssift.webviz
      cmdStr = "kill -9 {}".format(reportDaemonPID)    
      runInBackground = False
      okMsg = "Event reporting server stopped."
      callback = lambda : not self.getDaemonStatus()[1]
    else:
      #dnssift.webviz
      cmdStr = "python -m dnssift.webviz 2> {} 1> /dev/null".format(CMD_LOG_FILE)
      okMsg = "Event reporting server started!"
      callback = lambda : self.getDaemonStatus()[1]
    self.shellCmd(cmdStr, okMsg, callback, runInBackground)
    self.getDaemonStatus()
  
  def animateProgressBar(self, pb):
    pb.grid(row=0, sticky="ne")
    pb.start()    
    self.progressbarRunning = True
    def callback():
      if not self.progressbarRunning:
        pb.stop()
        pb.grid_remove()
      else: self.window.after(250, callback)
    self.window.after(250, callback)
  
  def startProgressbar(self):
    progressbar = ttk.Progressbar(self.progressFrame, orient="horizontal", length=500, mode="indeterminate")
    thread = threading.Thread(target=self.animateProgressBar, args=[progressbar])
    thread.daemon = True
    self.progressbarRunning = True
    thread.start()    
    return thread
  
  def stopProgressbar(self):
    self.progressbarRunning = False
    return
  
  def readErrLog(self, logfile):
    if os.path.isfile(logfile):
      with open(logfile) as f:
        lines = f.readlines()
        ret = "\n".join(lines)
        f.close()
        return ret
    return ""
  
  def readPIDFile(self, pidfile):
    pid = -1
    if os.path.isfile(pidfile):      
      with open(pidfile, "r") as f:
        try:
          pid = int(f.readline())
        except ValueError:pass   
        f.close()
    return pid

  def isProcAlive(self, pid):
    """Read process status from procfs, return False if the process is a zombie or was terminated."""
    statfname = "/proc/{}/stat".format(pid)
    ret = False
    if os.path.isfile(statfname):
      with open(statfname, "r") as statfile:
        statlineVars = statfile.readline().split()
        #Consider the process alive if state is neither 'Z' (zombie) nor 'T' (traced/stopped)
        ret = statlineVars[2] in "RSDW"
      statfile.close()
    return ret
  
  def reconfigureButtonState(self, button, st):
    if button != None:
      button.config(state=st)
    return
  
  def queryFunc(self, func, resultCb, wait_secs=2, step=0.25):
    """Returns the result of evaluating func() at least twice, with a delayed third evaluation if no changes"""
    ret = func()
    step = int(1000 * step)    
    self.startProgressbar()
    if func() == ret:
      iTim = time.time() + wait_secs
      def callback():
        if time.time() <= iTim : self.window.after(step, callback)
        else: 
          self.stopProgressbar()
          resultCb(func())
      self.window.after_idle(callback)
    else: resultCb(func())
  
  def getDaemonStatus(self):
    """
    Update the status of the main daemons.
    """
    configs = cfg.parseConf()
    pidfile = configs['filter_daemon_pidfile']
    report_daemon_pidfile = configs['reporter_daemon_pidfile']
    mainDaemonPID = self.readPIDFile(pidfile)    
    reportDaemonPID = self.readPIDFile(report_daemon_pidfile)
    if self.isProcAlive(mainDaemonPID):
      self.mainDaemonAlive = True
      self.filterStatusStr.set(" \t Running (PID {}) ".format(mainDaemonPID))
      self.filterControlButStr.set("STOP FILTER DAEMON")
      self.reconfigureButtonState(self.reportServerBut, NORMAL)
    else:
      self.mainDaemonAlive = False
      self.filterStatusStr.set(" \t Not running ")
      self.filterControlButStr.set("START FILTER DAEMON") 
      self.reconfigureButtonState(self.reportServerBut, DISABLED)
    if self.isProcAlive(reportDaemonPID):
      self.reportServerAlive = True
      self.reportClientStatusStr.set(" \t Running (PID {}) ".format(reportDaemonPID))
      self.reportClientControlButStr.set("STOP REPORT WEB SERVER")
    else:
      self.reportServerAlive = False
      self.reportClientStatusStr.set(" \t Not running ")
      self.reportClientControlButStr.set("START REPORT WEB SERVER")    
    return (self.mainDaemonAlive, self.reportServerAlive)
    
  def parseNS(self, resolvConfPath):
    """
    Retrieve list of configured nameserves
    """
    with open(resolvConfPath, "r") as f:
      lines = f.readlines()
      servers = []
      for line in lines:
        line = line.strip()
        if line[:10] == "nameserver":
          toks = line.split()
          if len(toks) == 2:
            servers.append(toks[1])
      f.close()
      self.nsListStr.set(", ".join(servers))
    return

root = Tk()
app = App(root)
root.mainloop()