/******************************************************************************
 * pam_sotp: Simple One Time Password support for PAM                         *
 *                                                                            *
 * This program is free software; you can redistribute it and/or modify       *
 * it under the terms of the GNU General Public License as published by       *
 * the Free Software Foundation; either version 2 of the License, or          *
 * (at your option) any later version.                                        *
 *                                                                            *
 * This program is distributed in the hope that it will be useful,            *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 * GNU General Public License for more details.                               *
 *                                                                            *
 * You should have received a copy of the GNU General Public License          *
 * along with this program; if not, write to the Free Software                *
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA  *
 *                                                                            *
 ******************************************************************************/


/* INCLUDES */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sotp_err.h"

/* GLOBAL VARIABLES */
char *errstr=NULL;
int sotp_errno;

char *errno_strings[] ={
	"Unknown error",
	"I/O Error",
	"Locking error",
	"Invalid authentication database",
	"Authentication database contains no password entries",
	"Entry seek error",
	"Invalid argument to function"
};
		

/* PUBLIC API */
char *sotp_error_string( void ) {
	
	char *ret;
	
	/* Some checks */
	if (sotp_errno > SOTP_ERR_NUM) 
		return NULL;
	
	/* Allocate and format the return string */
	if (errstr){ 
		ret = (char*) malloc( (size_t) strlen(errno_strings[sotp_errno-1]) + strlen(errstr) + 2 );
		sprintf( ret, "%s:%s", errno_strings[sotp_errno-1], errstr );
	} else {
		ret = strdup( errno_strings[sotp_errno-1] );
	}

	/* Free the error string */
	if (errstr != NULL)
		free( errstr );

	errstr = NULL;

	/* Return */
	return ret;
}
