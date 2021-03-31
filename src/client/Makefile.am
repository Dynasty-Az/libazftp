EXTRA_DIST = $(top_srcdir)/src/client/*.h

SUBDIRS = . bin
#INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/src/core

libazftpclilibdir = $(libdir)/libazftp

libazftpclilib_LTLIBRARIES = libazftpcli.la

libazftpcli_la_SOURCES = $(top_srcdir)/src/core/az_ftp_format.c \
$(top_srcdir)/src/core/az_ftp_code.c \
$(top_srcdir)/src/core/az_ftp_message.c \
$(top_srcdir)/src/core/az_ftp_tools.c \
az_ftp_climsg.c \
az_ftp_client_ctrl.c \
az_ftp_client_dtp.c \
az_ftp_client_pi.c

libazftpcli_la_CPPFLAGS = -DLIBAZFTPCLI_EXPORTS -fPIC -shared -I$(top_srcdir)/include -I$(top_srcdir)/src/core
libazftpcli_la_LDFLAGS = -version-info @lt_major@:@lt_revision@:@lt_age@
