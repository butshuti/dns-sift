#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([dns_sift], [0.1], [theogenebucuti@my.unt.edu])
AC_CONFIG_HEADERS([config.h])

dnl macro that checks for specific modules in python
AC_DEFUN([AC_PYTHON_MODULE],
[AC_MSG_CHECKING(for module $1 in python)
echo "import $1" | python -
if test $? -ne 0 ; then
AC_MSG_RESULT(not found)
AC_MSG_ERROR(The $1 module is required, but was not found in your python modules)
fi
AC_MSG_RESULT(found)
])


# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S

# Checks dependencies.
AC_CHECK_LIB([netfilter_queue], [nfq_open],[], AC_MSG_FAILURE([libnetfilter_queue is required but not found on the system. Please install it first.], 1))
AC_PYTHON_MODULE(Tkinter)
AC_PYTHON_MODULE(numpy)
AC_PYTHON_MODULE(matplotlib)

# Checks for header files.
CFLAGS="$CFLAGS -I/usr/include/python2.7"
AC_CHECK_HEADERS([pcap/pcap.h netinet/ip.h stdint.h syslog.h Python.h], [], AC_MSG_FAILURE([One or more required headers are missing. Please check the report above.]))

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_ALLOCA
AC_CHECK_FUNCS([memmove memset strchr strndup strtol])

AC_DEFINE([MODEL_SYSTEM_FLOW_THRESHOLDS], 1, [Configure the library adaptively change thresholds based on moving averages in the network flow.]) 


# Generate binaries
EXEC_NAME="dns_sift"
EXEC_CMD="dns_sift"
LIB_NAME="dns_sift.so"
OBJECT_NAME="dnssift.o"
PACKAGE_NAME="dnssift"
AC_SUBST(exec_name, $EXEC_NAME)
AC_SUBST(exec_cmd, $EXEC_CMD)
AC_SUBST(lib_name, $LIB_NAME)
AC_SUBST(object_name, $OBJECT_NAME)
AC_SUBST(package_name, $PACKAGE_NAME)

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([setup.py])
AC_CONFIG_FILES([start.sh])
AC_CONFIG_FILES([start.py])
AC_CONFIG_FILES([configutils.py])
AC_CONFIG_FILES([interface.py:src/gui/interface.py])
AC_CONFIG_FILES([webviz.py:src/classifier/py/classifierviz.py])
AC_CONFIG_FILES([cherrypy.conf:src/classifier/config/cherrypy.conf])
AC_CONFIG_FILES([engine.conf])

AC_OUTPUT
