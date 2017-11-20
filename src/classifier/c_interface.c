#include <stdio.h>
#include <stdlib.h>
#include <Python.h>
#include <signal.h>

static PyObject* classifyFunction = NULL;

PyObject *pyListFromCArray(int array[], size_t size); //forward

int train(void)
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
    PyObject* moduleString = PyString_FromString((char*)"dnssift.classifier_svm");
    PyObject* classifier_module = PyImport_Import(moduleString);
    PyObject* trainFunction = PyObject_GetAttrString(classifier_module, (char*)"train");
    if(trainFunction == NULL)
    {
    	PyErr_Print();
    	raise(SIGTERM);
    }
    classifyFunction = PyObject_GetAttrString(classifier_module, (char*)"classify");
    if(classifyFunction == NULL)
    {
    	PyErr_Print();
    	Py_CLEAR(trainFunction);
    	raise(SIGTERM);
    }
    PyObject* temp = PyObject_CallObject(trainFunction, NULL);
    if(temp == NULL){
    	PyErr_Print();
    	Py_CLEAR(trainFunction);
    	Py_CLEAR(classifyFunction);
    	raise(SIGTERM);
    }
    int success = PyInt_AsLong(temp);
    Py_CLEAR(temp);
    fprintf(stderr, "c_interface: Training ending?: <%s>.\n", (Py_IsInitialized() && success == 0) ? "TRUE" : "FALSE");
    return classifyFunction != NULL && success == 0;
}
int classify(int arr[], int size, const char *tag)
{
	if(classifyFunction == NULL){
		fprintf(stderr, "classifyFunction is NULL: classifier not trained.\n");
		exit(-1);
	}
	//acquire Python's Global Interpreter Lock (GIL)
	PyGILState_STATE gstate;
   gstate = PyGILState_Ensure();
   //Call the needed Python functions using the Python API
	PyObject* py_arr = pyListFromCArray(arr, size);
	PyObject* py_str = PyString_FromString(tag);
	PyObject *arglist = PyTuple_Pack(2, py_arr, py_str);
	PyObject* retObj = PyObject_CallObject(classifyFunction, arglist);
	int ret = PyInt_AsLong(retObj);
	Py_CLEAR(py_arr);
	Py_CLEAR(arglist);
	Py_CLEAR(retObj);
	//Release the GIL
	PyGILState_Release(gstate);
	//Return result
	return ret;
}
int classify_flow(int arr[], int size, const char *tag)
{
	return classify(arr, size, tag);
}
int Obslt_main(int argc, char **argv)
{
	int arr[] = {0, 1, 1, 81, 1, 1, 1}, arr2[] = {0, 3, 3, 3, 3, 3, 3}, 
		arr3[] = {32, 0, 0, 0, 40, 64, 32}, arr4[] = {48, 0, 0, 0, 40, 64, 0};
	
	int* arrs[] = {arr, arr2, arr3, arr4};
	train();
	size_t i;
	for(i=0; i<4; i++){
		int ret = classify(arrs[i], 7, "test");
		printf("Result: %d\n", ret);
	}
    /* Exit, cleaning up the interpreter */
    Py_Exit(0);
    /*NOTREACHED*/
    return -1;
}

PyObject *pyListFromCArray(int array[], size_t arr_siz) {
    PyObject *ret = PyList_New(arr_siz);
    size_t i;
    for (i = 0; i != arr_siz; i++) {
        PyList_SET_ITEM(ret, i, PyInt_FromLong(array[i]));
    }
    return ret;
}

