
svnver = $(shell git describe --all --dirty --long --abbrev=40)

AM_CPPFLAGS = -DSVN_REVISION="\"Configure=@SVN_REVISION@,Make=$(svnver)\""     \
              -DSVN_REVISION_N="\"$(svnver)\""                                 \
              -I@top_builddir@ -I$(top_srcdir)/include                         \
			  @S28YPT_CFLAGS@


bin_PROGRAMS = s28ypt

s28ypt_LDADD = @S28YPT_LIBS@
s28ypt_SOURCES = cyp.cc safemem.cc textutils.cc file.cc

