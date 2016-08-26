from Tkinter import *
import subprocess

class App:
  def __init__(self, window):
    self.mainDaemonPID = -1
    self.reportDaemonPID = -1
    self.getDaemonStatus()
    self.window = window
    self.nsListStr = StringVar(self.window)
    self.filterStatusStr = StringVar(self.window)
    self.reportClientStatusStr = StringVar(self.window)
    self.filterControlButStr = StringVar(self.window, "START")
    self.reportClientControlButStr = StringVar(self.window, "START")
    Frame(self.window,width=600,height=10).pack(side=TOP)
    self.home()
    Frame(self.window,width=600,height=10).pack(side=TOP)
    self.window.resizable(width=False, height=False)
    
  def home(self):
    #Configured NS info frame
    nsFrame = Frame(self.window, relief="groove", borderwidth=1)
    Label(nsFrame, text="Configured nameservers:", height=2, anchor='w').grid(row=0, sticky="nsew")
    Label(nsFrame, textvariable=self.nsListStr, relief="sunken").grid(row=1, sticky="nsew")
    nsFrame.pack(side=TOP, fill=X, padx=20, pady=10, ipadx=20, ipady=5)
    #filter daemon status frame
    statusFrame = Frame(self.window, relief="groove", borderwidth=1)
    Label(statusFrame, text="DNS filter status:", height=2, anchor='w').grid(row=0, column=0)
    Label(statusFrame, textvariable=self.filterStatusStr).grid(row=0, column=1)
    Button(statusFrame, textvariable=self.filterControlButStr, command=self.changeFilterStatus).grid(row=1, column=0, sticky=W)
    statusFrame.pack(side=TOP, fill=X, padx=20, pady=10, ipadx=20, ipady=5)
    #web report client frame
    reportClientFrame = Frame(self.window, relief="groove", borderwidth=1)
    Label(reportClientFrame, text="Realtime report client status:", height=2, anchor='w').grid(row=0, column=0)
    Label(reportClientFrame, textvariable=self.reportClientStatusStr).grid(row=0, column=1)
    Button(reportClientFrame, textvariable=self.reportClientControlButStr, command=self.changeReportClientStatus).grid(row=1, column=0, sticky=W)
    reportClientFrame.pack(side=TOP, fill=X, padx=20, pady=10, ipadx=20, ipady=5)
    return
    
  def changeFilterStatus(self):
    pass
  
  def changeReportClientStatus(self):
    pass
  
  def getDaemonStatus(self):
    p = subprocess.Popen()
    pass
    

root = Tk()
app = App(root)
root.mainloop()