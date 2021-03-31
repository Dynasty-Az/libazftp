EXTRA_DIST = $(top_srcdir)/src/server/*.h

SUBDIRS = . bin
#INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/src/core

libazftpdlibdir = $(libdir)/libazftp

libazftpdlib_LTLIBRARIES = libazftpd.la

libazftpd_la_SOURCES = $(top_srcdir)/src/core/az_ftp_format.c \
$(top_srcdir)/src/core/az_ftp_code.c \
$(top_srcdir)/src/core/az_ftp_message.c \
$(top_srcdir)/src/core/az_ftp_tools.c \
az_ftp_response.c \
az_ftp_server_dtp.c \
az_ftp_server_pi.c \
az_ftp_server.c

libazftpd_la_CPPFLAGS = -DLIBAZFTPSER_EXPORTS -fPIC -shared -I$(top_srcdir)/include -I$(top_srcdir)/src/core
libazftpd_la_LDFLAGS = -version-info @lt_major@:@lt_revision@:@lt_age@
