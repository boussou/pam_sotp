#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(pam_sotp, 0.3.3, [Pedro Diaz <sotp@cavecanen.org>] )
AC_CONFIG_SRCDIR([src/lib/libsotp.c])
AC_CONFIG_SRCDIR([src/libsotp/sotp_db.c])
AC_CONFIG_AUX_DIR( .config/ )
AC_DEFINE( CONFIG_SOTP_VERSION, "0.3.3" )
AC_PREFIX_DEFAULT( "/usr/local/" )

# Set CFLAGS
if test -z "$CFLAGS"; then
	CFLAGS="-O -Wall"
else 
	CFLAGS="$CFLAGS -Wall"
fi

# Command line arguments
AC_ARG_ENABLE( [debug],
	AC_HELP_STRING( [--enable-debug],[enable debug (default is NO)] ),
	[AC_DEFINE(CONFIG_DEBUG)],[my_dummy="1"] )

AC_ARG_WITH( [randomdev],
	[AC_HELP_STRING( [--with-randomdev],[Select the device that will be used to gather random data (default is /dev/random)] )],
	[my_randomdev="$withval"], [my_randomdev="/dev/random"] )

AC_ARG_WITH( [authdir],
	[AC_HELP_STRING( [--with-authdir], [Select the default authentication directory (default is /etc/sotp/)] )],
	[
	AC_SUBST( AUTH_DIR_DEFAULT, "$withval/" )
	AC_DEFINE_UNQUOTED( CONFIG_AUTH_DIR_DEFAULT, "$withval/" )
	],
	[
	AC_SUBST( AUTH_DIR_DEFAULT, "/etc/sotp/" )
	AC_DEFINE_UNQUOTED( CONFIG_AUTH_DIR_DEFAULT, "/etc/sotp/" )
	]
	)


# Checks for programs.
AC_PROG_CC
AC_PROG_EGREP
AC_PROG_INSTALL
AC_PROG_RANLIB

# For now pam_sotp only works with gcc. We won't accept substitutes ;-)
if test "$CC" != "gcc" ; then
	AC_MSG_CHECKING( [that the compiler is actually GCC] )
	# Maybe it is an alias or something
	if ! ( $CC -v 2>&1 | $EGREP "^gcc version" > /dev/null ) ; then
		AC_MSG_ERROR( [Sorry, for now pam_sotp only compiles under gcc] )
	else
		AC_MSG_RESULT( [ok] )
	fi
fi

AC_CHECK_PROG( [prog_ld], [ld], [yes], [no] )
if test "$prog_ld" = "no" ; then
	AC_MSG_ERROR( [ld not found!] )
fi

# Random device check
if test -c "$my_randomdev" ; then 
	AC_DEFINE_UNQUOTED( [CONFIG_RND_DEV], ["$my_randomdev"] )
fi


# Library Checks.
AC_CHECK_LIB([c], [sprintf])
AC_CHECK_LIB([pam], [pam_start], [], [AC_MSG_ERROR( [You don't seem to have installed the PAM development package] )] )


# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h termios.h unistd.h sys/types.h netinet/in.h security/pam_modules.h security/pam_appl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_UID_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_MALLOC
AC_FUNC_MEMCMP

                    
# Check for the shadow group
AC_MSG_CHECKING( [Checking for the 'shadow' group] )
if egrep '^shadow:' /etc/group &> /dev/null ; then
	AC_MSG_RESULT( [ok] )
else 
	AC_MSG_ERROR( ['shadow' group not found!. This is strange, but anyways you could try to create it by yourself] )
fi

# Checks for standard PAM directories
AC_MSG_NOTICE( [testing standard PAM directories] )

AC_MSG_CHECKING( [/lib/security] )
if test -d /lib/security ; then
	AC_MSG_RESULT( [ok] )
	AC_SUBST( PAM_MODULEDIR, "/lib/security/" )
else
	AC_MSG_ERROR( [No /lib/security!] )
fi

AC_MSG_CHECKING( [/etc/pam.d] )
if test -d /etc/pam.d ; then
	AC_MSG_RESULT( [ok] )
	AC_SUBST( PAM_CONFIGDIR, "/etc/pam.d/" )
else
	AC_MSG_ERROR( [No /etc/pam.d] )
fi


AC_CONFIG_HEADERS( [src/config.h] )

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/libsotp/Makefile
                 src/pam/Makefile
                 src/utils/Makefile])
AC_OUTPUT
