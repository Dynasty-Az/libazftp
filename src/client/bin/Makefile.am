EXTRA_DIST = $(top_srcdir)/src/client/bin/*.h
#INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/src/log/include

bin_PROGRAMS = azftpcli

azftpcli_SOURCES = cmd_histroy.c \
main.c

azftpcli_CPPFLAGS = -I$(top_srcdir)/include
azftpcli_LDADD = $(top_srcdir)/src/client/libazftpcli.la

#azftpcli_confdir = /etc/
#azftpcli_conf_DATA = 
