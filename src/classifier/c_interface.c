#include <stdio.h>
#include <stdlib.h>
#include <Python.h>

static PyObject* classifyFunction = NULL;

PyObject *pyListFromCArray(int array[], size_t size); //forward

int train()
{
	fprintf(stderr, "c_interface: Training starting.\n");
	/* Initialize the Python interpreter.  Required. */
    Py_InitializeEx(0);
    /* Define sys.argv.  
       If the third argument is true, sys.path is modified to include
       either the directory containing the script named by argv[0], or
       the current working directory.  This can be risky; if you run
       an application embedding Python in a directory controlled by
       someone else, attackers could put a Trojan-horse module in the
       directory (say, a file named os.py) that your application would
       then import and run.
    */
    /*fprintf(stderr, "Demo warning: Adding current working directory to sys.path. Note: This can be dangerous as it is vulnerable to malicious injection if the directory is controlled by someone untrusted.\n");
    extern char *__progname;
    char* argv[] = {__progname};
    PySys_SetArgvEx(1, argv, 0);*/
    PyObject* moduleString = PyString_FromString((char*)"dnssift.classifier");
    PyObject* classifier_module = PyImport_Import(moduleString);
    PyObject* trainFunction = PyObject_GetAttrString(classifier_module, (char*)"train");
    if(trainFunction == NULL)
    {
    	PyErr_Print();
    	exit(-1);
    }
    classifyFunction = PyObject_GetAttrString(classifier_module, (char*)"classify");
    if(classifyFunction == NULL)
    {
    	PyErr_Print();
    	Py_CLEAR(trainFunction);
    	exit(-1);
    }
    PyObject* temp = PyObject_CallObject(trainFunction, NULL);
    if(temp == NULL){
    	PyErr_Print();
    	Py_CLEAR(trainFunction);
    	Py_CLEAR(classifyFunction);
    	exit(-1);
    }
    Py_CLEAR(temp);
    fprintf(stderr, "c_interface: Training ending?: <%s>.\n", Py_IsInitialized() ? "TRUE" : "FALSE");
    return classifyFunction != NULL;
}

int classify(int arr[], int size)
{
	if(classifyFunction == NULL){
		fprintf(stderr, "classifyFunction is NULL: classifier not trained.\n");
		exit(-1);
	}
	PyObject* py_arr = pyListFromCArray(arr, size);
	PyObject *arglist = PyTuple_Pack(1, py_arr);
	PyObject* retObj = PyObject_CallObject(classifyFunction, arglist);
	int ret = PyInt_AsLong(retObj);
	Py_CLEAR(py_arr);
	Py_CLEAR(arglist);
	Py_CLEAR(retObj);
	return ret;
}

Obslt_main(int argc, char **argv)
{
	int arr[] = {0, 1, 1, 81, 1, 1, 1}, arr2[] = {0, 3, 3, 3, 3, 3, 3}, 
		arr3[] = {32, 0, 0, 0, 40, 64, 32}, arr4[] = {48, 0, 0, 0, 40, 64, 0};
	
	int* arrs[] = {arr, arr2, arr3, arr4};
	train();
	size_t i;
	for(i=0; i<4; i++){
		int ret = classify(arrs[i], 7);
		printf("Result: %d\n", ret);
	}
    /* Exit, cleaning up the interpreter */
    Py_Exit(0);
    /*NOTREACHED*/
}

PyObject *pyListFromCArray(int array[], size_t arr_siz) {
    PyObject *ret = PyList_New(arr_siz);
    size_t i;
    for (i = 0; i != arr_siz; i++) {
        PyList_SET_ITEM(ret, i, PyInt_FromLong(array[i]));
    }
    return ret;
}

