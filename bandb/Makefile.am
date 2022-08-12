pkglibexec_PROGRAMS = bandb
bin_PROGRAMS = bantool
AM_CFLAGS=$(WARNFLAGS)

AM_CPPFLAGS = -I../include -I../librb/include @SQLITE_INCLUDES@

bandb_SOURCES = bandb.c rsdb_sqlite3.c rsdb_snprintf.c
bandb_LDADD = ../librb/src/librb.la @SQLITE_LD@

bantool_SOURCES = bantool.c rsdb_sqlite3.c rsdb_snprintf.c
bantool_LDADD = ../librb/src/librb.la @SQLITE_LD@
