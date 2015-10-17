#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([dns_sift], [0.1], [theogenebucuti@my.unt.edu])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S

# Checks dependencies.
AC_CHECK_LIB([netfilter_queue], [nfq_open],[], AC_MSG_FAILURE([libnetfilter_queue is required but not found on the system. Please install it first.], 1))

# Checks for header files.
AC_CHECK_HEADERS([netinet/ip.h linux/netfilter.h stdint.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_ALLOCA
AC_CHECK_FUNCS([memmove memset strchr strndup strtol])

# Generate binaries
EXEC_NAME="./bin/dns_sift"
LIB_NAME="./bin/dns_sift.so"
AC_SUBST(exec_name, $EXEC_NAME)
AC_SUBST(lib_name, $LIB_NAME)

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([start.sh])

AC_OUTPUT
