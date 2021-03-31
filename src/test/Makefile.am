#EXTRA_DIST = $(top_srcdir)/src/test

#INCLUDES = -I$(top_srcdir)/include

noinst_PROGRAMS = test-client

test_client_SOURCES = test-client.c
test_client_CPPFLAGS = -I$(top_srcdir)/include
test_client_LDADD = $(top_srcdir)/src/client/libazftpcli.la
