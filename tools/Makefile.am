bin_PROGRAMS = mkpasswd mkfingerprint
AM_CFLAGS=$(WARNFLAGS)
AM_CPPFLAGS = $(DEFAULT_INCLUDES) -I../librb/include -I.

mkpasswd_SOURCES = mkpasswd.c
mkpasswd_LDADD = ../librb/src/librb.la

mkfingerprint_SOURCES = mkfingerprint.c
mkfingerprint_LDADD = ../librb/src/librb.la
