#INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/src/log/include

bin_PROGRAMS = azftpd

azftpd_SOURCES = main.c

azftpd_CPPFLAGS = -I$(top_srcdir)/include
azftpd_LDADD = $(top_srcdir)/src/server/libazftpd.la

azftpd_confdir = /etc/
azftpd_conf_DATA = $(top_srcdir)/cnf/azftpd.cnf $(top_srcdir)/cnf/.azftpd_auth
