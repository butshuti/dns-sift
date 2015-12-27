#include <stdio.h>
#include <stdlib.h>
#include <Python.h>

static PyObject* classifyFunction = NULL;

PyObject *pyListFromCArray(int array[], size_t size); //forward

int train()
{
	/* Initialize the Python interpreter.  Required. */
    Py_Initialize();
    /* Define sys.argv.  
       If the third argument is true, sys.path is modified to include
       either the directory containing the script named by argv[0], or
       the current working directory.  This can be risky; if you run
       an application embedding Python in a directory controlled by
       someone else, attackers could put a Trojan-horse module in the
       directory (say, a file named os.py) that your application would
       then import and run.
    */
    fprintf(stderr, "Demo warning: Adding current working directory to sys.path. Note: This can be dangerous as it is vulnerable to malicious injection if the directory is controlled by someone untrusted.\n");
    extern char *__progname;
    char* argv[] = {__progname};
    PySys_SetArgvEx(1, argv, 1);
    PyObject* moduleString = PyString_FromString((char*)"classifier_C_interface");
    PyObject* classifier_module = PyImport_Import(moduleString);
    if(classifier_module == NULL)
    {
    	PyErr_Print();
    	exit(-1);
    }
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
    	exit(-1);
    }
    PyObject* temp = PyObject_CallObject(trainFunction, NULL);
    if(temp == NULL){
    	return 0;
    }
    Py_DECREF(temp);
    fprintf(stderr, "Training ended.\n");
    return classifyFunction != NULL;
}

int classify(int arr[], int size)
{
	if(classifyFunction == NULL){
		fprintf(stderr, "classifyFunction is NULL: classifier not trained.\n");
		exit(-1);
	}
	PyObject* py_arr = pyListFromCArray(arr, 7);
	PyObject *arglist = PyTuple_Pack(1, py_arr);
	PyObject* retObj = PyObject_CallObject(classifyFunction, arglist);
	int ret = PyInt_AsLong(retObj);
	Py_DECREF(py_arr);
	Py_DECREF(arglist);
	Py_DECREF(retObj);
	return ret;
}

main(int argc, char **argv)
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

