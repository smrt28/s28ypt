# initialize autoconf
AC_INIT([s28ypt], [1.0.0], [ondrej.holecek@firma.seznam.cz])
VERSION_INFO="-version-info 0:0:0"

# install autotools scripts to build-aux dir
AC_CONFIG_AUX_DIR([build-aux])

# initialize automake(use AC_INIT's arguments)
AM_INIT_AUTOMAKE([-Wall foreign])

# Enable silent builds (disable with --disable-silent-rules)
# or simply do "make V=1"
AM_SILENT_RULES([yes])

# tell autoconf where to find sources
AC_CONFIG_SRCDIR([src/cyp.cc])
AC_CONFIG_HEADER([config.h])

dnl This forces debian autoconf to use version 2.53
AC_PREREQ(2.50)

# disable so
AC_DISABLE_SHARED

# initialize libtool
AC_PROG_LIBTOOL

# Add a test for a compiler.
AC_PROG_CC
AC_PROG_CXX

# replace autotools original defaults
CXXFLAGS="-W -Wall -Wextra -Wconversion"


AC_SUBST(MALLOC_LIB)

SVN_REVISION="`git describe --all --dirty --long --abbrev=40`"

AC_SUBST(SVN_REVISION)
AC_SUBST(VERSION_INFO)

PKG_PROG_PKG_CONFIG


S28YPT_DEPS="openssl"
PKG_CHECK_MODULES([S28YPT], [${S28YPT_DEPS}])

AC_LANG_CPLUSPLUS


# Write config.status and the Makefile
AC_CONFIG_FILES([Makefile src/Makefile version])

AC_OUTPUT()
