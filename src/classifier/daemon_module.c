#include <Python.h>
#include "qh_daemon.h"
#include "logger.h"

static void thread_switch_wrapper(void (*f)(void)){
	 	Py_BEGIN_ALLOW_THREADS
	 	f();
	 	Py_END_ALLOW_THREADS
}
	 
static PyObject* daemon_start(PyObject *self, PyObject *args)
{
    char *mode_arg, *iface_arg, *debug_level_arg;
    int mode = STRICT;
    if(!PyArg_ParseTuple(args, "sss", &mode_arg, &iface_arg, &debug_level_arg)){
    	perror("PyArg_ParseTuple");
    	fprintf(stderr, "Error parsing arguments.\n");
    	fprintf(stderr, "Arguments format: (1:str<mode=[STRICT|PERMISSIVE|LEARNING]>, 2:str<debug=[VERBOSE|WARN|OFF]>).\n");
    	return Py_BuildValue("d", -1);
    }
    if(strncmp(mode_arg, "STRICT", strlen("STRICT")) == 0){
    	mode = STRICT;
    }else if(strncmp(mode_arg, "PERMISSIVE", strlen("PERMISSIVE")) == 0){
    	mode = PERMISSIVE;
    }else if(strncmp(mode_arg, "LEARNING", strlen("LEARNING")) == 0){
    	mode = LEARNING;
    }else{
    	fprintf(stderr, "Unrecognized argument for --mode:%s\n", mode_arg);
    	return Py_BuildValue("d", -1);
    }
    if(strncmp(debug_level_arg, "VERBOSE", strlen("VERBOSE")) == 0){
    	fprintf(stderr, "Setting debug level to %s/VERBOSE. Use -h for how to change debug levels\n", debug_level_arg);
    	set_log_level(LOG_LEVELS_VERBOSE);
    }else if(strncmp(debug_level_arg, "INFO", strlen("INFO")) == 0){
    	set_log_level(LOG_LEVELS_INFO);
    }else if(strncmp(debug_level_arg, "WARN", strlen("WARN")) == 0){
    	set_log_level(LOG_LEVELS_WARNING);
    }else if(strncmp(debug_level_arg, "OFF", strlen("OFF")) == 0){
    	fprintf(stderr, "Setting debug level to %s/CRITICAL only. Use -h for how to change debug levels\n", debug_level_arg);
    	set_log_level(LOG_LEVELS_CRITICAL);
    }
    pkt_divert_start(mode, iface_arg, &thread_switch_wrapper);
    return Py_BuildValue("d", 0);
}

static char module_docstring[] = "This module provides an interface for calling dnssift from python.";
static char start_daemon_docstring[] = "Start the packet handler daemon.";
    
static PyMethodDef module_methods[] = {
    {"start_daemon", daemon_start, METH_VARARGS, start_daemon_docstring},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initdaemon(void)
{
    PyObject *m = Py_InitModule3("daemon", module_methods, module_docstring);
    // Make sure the Global Interpreter Lock has been created to properly initialize threading
	 if(!PyEval_ThreadsInitialized()){
		 PyEval_InitThreads();
	 }
    if(m == NULL){
    	return;
    }
    PyObject *errObj =  PyErr_NewException("daemon.error", NULL, NULL);
    Py_INCREF(errObj);
    PyModule_AddObject(m, "error", errObj);
}


