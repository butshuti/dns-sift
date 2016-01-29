#include <Python.h>
#include "qh_daemon.h"

static PyObject* daemon_start(PyObject *self, PyObject *args)
{
    pkt_divert_start();
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
    if(m == NULL){
    	return;
    }
    PyObject *errObj =  PyErr_NewException("daemon.error", NULL, NULL);
    Py_INCREF(errObj);
    PyModule_AddObject(m, "error", errObj);
}


