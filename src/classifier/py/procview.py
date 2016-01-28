import sys, subprocess, time, random
from events import *

MEM_EVENT_NAME = "pmem"
CPU_EVENT_NAME = "pcpu"
ETIMES_EVENT_NAME = "etimes"
START_EVENT_NAME = "bsdstart"
COMM_EVENT_NAME = "command"
PROC_EVENT_CODE = "proc"

PROC_SYS_USED_MEM_FEATURE_POS = 0
PROC_SYS_USED_CPU_FEATURE_POS = 1
PROC_INDIV_PMEM_FEATURE_POS = 2
PROC_INDIV_PCPU_FEATURE_POS = 3
PROC_NUM_TASKS_FEATURE_POS = 4

class ProcView(BaseEventHandler):
    DEAFULT_FILTER_COMMAND = "ps axc --no-headers -o {},{},{},{},{}".format(START_EVENT_NAME, MEM_EVENT_NAME, CPU_EVENT_NAME, ETIMES_EVENT_NAME, COMM_EVENT_NAME)
    STIME_FILTER_COMMAND = "ps axc --no-headers -o {},{},{},{},{}".format(START_EVENT_NAME, MEM_EVENT_NAME, CPU_EVENT_NAME, ETIMES_EVENT_NAME, COMM_EVENT_NAME)
    PMEM_FILTER_COMMAND = "ps axc --no-headers -o {},{},{},{},{}".format(MEM_EVENT_NAME, CPU_EVENT_NAME, ETIMES_EVENT_NAME, START_EVENT_NAME, COMM_EVENT_NAME)
    PCPU_FILTER_COMMAND = "ps axc --no-headers -o {},{},{},{},{}".format(CPU_EVENT_NAME, MEM_EVENT_NAME, ETIMES_EVENT_NAME, START_EVENT_NAME, COMM_EVENT_NAME)
    ETIMES_FILTER_COMMAND = "ps axc --no-headers -o {},{},{},{},{}".format(ETIMES_EVENT_NAME, MEM_EVENT_NAME, CPU_EVENT_NAME, START_EVENT_NAME, COMM_EVENT_NAME)
    QUERY_COMMAND = "watch -n {} '{}' | sort -nr | head -n {}"
    DEFAULT_TIMEOUT = 10    #refresh timeout
    DEFAULT_LIMIT = 200  #50 top processes
    DEFAULT_QC = QUERY_COMMAND.format(DEFAULT_TIMEOUT, DEAFULT_FILTER_COMMAND, DEFAULT_LIMIT)
    FILTERS = {START_EVENT_NAME:STIME_FILTER_COMMAND, MEM_EVENT_NAME:PMEM_FILTER_COMMAND,
               CPU_EVENT_NAME:PCPU_FILTER_COMMAND, ETIMES_EVENT_NAME:ETIMES_FILTER_COMMAND,
               "default":DEAFULT_FILTER_COMMAND}
    
    def __init__(self, timeout=None, output_size=None, **kwargs):
        super(ProcView, self).__init__()
        if timeout>0:
            self.timeout = timeout
        else:
            self.timeout = ProcView.DEFAULT_TIMEOUT
        if output_size:
            self.output_size = output_size
        else:
            self.output_size = ProcView.DEFAULT_LIMIT
        self.query_command = ProcView.QUERY_COMMAND.format(self.timeout, ProcView.DEAFULT_FILTER_COMMAND, self.output_size)

    def parse_cmd_output_line(self, line, header, sep=' '):
        """ 
        Cannot use str.split(' ')  to extract fileds separated by multiple spaces, with the last one possibly having spaces in it
        """
        num_fields=len(header)
        toks=line.split(sep)
        fields=[it for it in toks if it!=sep and it!='']
        num_toks = len(fields)
        output={}
        for idx in range(len(header)):
            if idx == num_toks-1:output[header[idx]] = sep.join(fields[idx:]).strip('\n')
            else: output[header[idx]] = fields[idx].strip('\n')
        return output

    def topSummary(self):
        proc = subprocess.Popen(["top", "-b", "-n", "1"], stdout=subprocess.PIPE)
        summary = proc.stdout.readlines()[:5]
        header1 = summary[1].split(",")
        header2 = summary[2].split(": ")[1].split(",")
        header3 = summary[3].split(": ")[1].split(",")
        num_tasks = header1[2].strip().split(" ")[0]
        pcpu = header2[0].strip().split(" ")[0]
        mem_tot = header3[0].strip().split(" ")[0]
        mem_used = header3[1].strip().split(" ")[0]
        pmem = float(mem_used) / int(mem_tot)
        return {"pmem":pmem, "pcpu":pcpu, "num_tasks":num_tasks}
        
        
    def query(self, filter_arg="default"):
        if filter_arg not in ProcView.FILTERS:
            raise Exception("Unknown filter: {}. Filter must be one from {}".format(filter_arg, ProcView.FILTERS.keys()))
        cmd = ProcView.FILTERS[filter_arg].split(" ")
        output_filter_cmd = "head -n {}".format(self.output_size).split(" ")
        ps_proc = subprocess.Popen(cmd,stdout=subprocess.PIPE, close_fds=True)
        sorter_proc = subprocess.Popen(["sort", "-nr"], stdin=ps_proc.stdout, stdout=subprocess.PIPE, close_fds=True)
        collector_proc = subprocess.Popen(output_filter_cmd, stdin=sorter_proc.stdout, stdout=subprocess.PIPE, close_fds=True)
        output_keys = cmd[4:][0].split(",")
        cur_time = time.time()
        proc_summary = self.topSummary()
        for line in collector_proc.stdout:
            proc_info = self.parse_cmd_output_line(line, output_keys)
            timestamp = (cur_time - float(proc_info[ETIMES_EVENT_NAME]))/300
            evt = LabeledEvent(timestamp, PROC_EVENT_CODE, ETIMES_EVENT_NAME+proc_info[ETIMES_EVENT_NAME], proc_info[COMM_EVENT_NAME])
            evt.updateFeature(PROC_INDIV_PMEM_FEATURE_POS, float(proc_info[MEM_EVENT_NAME]))
            evt.updateFeature(PROC_INDIV_PCPU_FEATURE_POS, float(proc_info[CPU_EVENT_NAME]))
            self.registerEvent(evt)
            
    def pollEvents(self):
        filters = ProcView.FILTERS.keys()
        self.query(filters[random.randint(0, len(filters)-1)])
        
    def stop(self):
        pass