#                                              -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.


AC_PREREQ([2.63])

AC_INIT([libazftp], [m4_esyscmd([echo -n $(cat ./version)])], [449273151@qq.com])
AC_CONFIG_SRCDIR([include/azftp/az_ftp_define.h])
AC_CONFIG_SRCDIR([include/azftp/az_ftp_server.h])
AC_CONFIG_SRCDIR([include/azftp/az_ftp_client.h])

AC_CONFIG_SRCDIR([src/core/az_ftp_code.h])
AC_CONFIG_SRCDIR([src/core/az_ftp_code.c])
AC_CONFIG_SRCDIR([src/core/az_ftp_format.h])
AC_CONFIG_SRCDIR([src/core/az_ftp_format.c])
AC_CONFIG_SRCDIR([src/core/az_ftp_message.h])
AC_CONFIG_SRCDIR([src/core/az_ftp_message.c])
AC_CONFIG_SRCDIR([src/core/az_ftp_tools.h])
AC_CONFIG_SRCDIR([src/core/az_ftp_tools.c])

AC_CONFIG_SRCDIR([src/server/az_ftp_include.h])
AC_CONFIG_SRCDIR([src/server/az_ftp_response.c])
AC_CONFIG_SRCDIR([src/server/az_ftp_server.c])
AC_CONFIG_SRCDIR([src/server/az_ftp_server_dtp.c])
AC_CONFIG_SRCDIR([src/server/az_ftp_server_dtp.h])
AC_CONFIG_SRCDIR([src/server/az_ftp_server_pi.c])
AC_CONFIG_SRCDIR([src/server/az_ftp_server_pi.h])
AC_CONFIG_SRCDIR([src/server/bin/main.c])

AC_CONFIG_SRCDIR([src/client/az_ftp_include.h])
AC_CONFIG_SRCDIR([src/client/az_ftp_climsg.c])
AC_CONFIG_SRCDIR([src/client/az_ftp_client_pi.c])
AC_CONFIG_SRCDIR([src/client/az_ftp_client_dtp.c])
AC_CONFIG_SRCDIR([src/client/az_ftp_client_dtp.h])
AC_CONFIG_SRCDIR([src/client/az_ftp_client_ctrl.c])
AC_CONFIG_SRCDIR([src/client/az_ftp_client_ctrl.h])
AC_CONFIG_SRCDIR([src/client/bin/main.c])
AC_CONFIG_SRCDIR([src/client/bin/cmd_histroy.h])
AC_CONFIG_SRCDIR([src/client/bin/cmd_histroy.c])

AC_CONFIG_HEADERS([include/libazftpcnf.h])

lt_major=$(cat ./version|cut -d . -f 1)
lt_revision=$(cat ./version|cut -d . -f 2)
lt_age=$(cat ./version|cut -d . -f 3)

AM_INIT_AUTOMAKE([libazftp], [m4_esyscmd([echo -n $(cat ./version)])])
AC_CANONICAL_HOST

AC_SUBST([lt_major])
AC_SUBST([lt_age])
AC_SUBST([lt_revision])

# Checks for programs.
AC_PROG_CC
#AC_PROG_INSTALL
AC_PROG_LIBTOOL
# declare --enable-* args and collect ac_help strings
AM_PROG_CC_C_O

# Checks for libraries.
LDFLAGS="-L`echo -n $(cat /etc/ld.so.conf.d/libazctools.conf)`";
AC_CHECK_LIB([rt], [clock_gettime], [], [exit -1])
AC_CHECK_LIB([dl], [dlopen], [], [exit -1])
AC_CHECK_LIB([pthread], [pthread_mutex_init], [], [exit -1])
#AC_CHECK_LIB([ncursesw], [initscr], [], [exit -1])
AC_CHECK_LIB([azmemp], [az_memp_create], [], [exit -1])
AC_CHECK_LIB([aztools], [az_create_thread], [], [exit -1])
AC_CHECK_LIB([aztools], [az_cnf_parser], [], [exit -1])
AC_CHECK_LIB([azlist], [az_list_init], [], [exit -1])
AC_CHECK_LIB([azlog], [az_log_init], [], [exit -1])
AC_CHECK_LIB([aztaskp], [az_taskp_create], [], [exit -1])
AC_PROG_RANLIB

AC_DEFINE([PROJECT_HOME_URL], ["https://github.com/Dynasty-Az/libazftp"], [Project Home Page URL])
AC_DEFINE_UNQUOTED([AZ_MAJOR_VERSION], ${lt_major}, [Major version number of package])
AC_DEFINE_UNQUOTED([AZ_MINOR_VERSION], ${lt_revision}, [Minor version number of package])
AC_DEFINE_UNQUOTED([AZ_RELEASE_VERSION], ${lt_age}, [Release version number of package])
AC_DEFINE_UNQUOTED([AZ_BUILD_TIME], `date "+%s"`, [Project build UTC time])
if test "$prefix" = NONE; then
  AC_DEFINE_UNQUOTED([AZ_PREFIX_PATH], "${ac_default_prefix}", [Project default prefix path])
else
  AC_DEFINE_UNQUOTED([AZ_PREFIX_PATH], "${prefix}", [Project default prefix path])
fi

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h malloc.h mntent.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/statfs.h sys/time.h sys/timeb.h unistd.h azctools/az_memp.h azctools/az_tools.h azctools/az_platform.h azctools/az_log.h azctools/az_list.h azctools/az_taskp.h], [], [exit -1])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_TYPE_OFF_T

#AC_FUNC_MALLOC
AC_CHECK_FUNCS([getpagesize malloc memalign], [], [exit -1])

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 include/azftp/Makefile
                 src/Makefile
                 src/server/Makefile
                 src/server/bin/Makefile
                 src/client/Makefile
                 src/client/bin/Makefile
                 src/test/Makefile])

AC_OUTPUT
