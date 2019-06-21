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


#ifndef _SOTP_ERR_H_
#define _SOTP_ERR_H_


/* ERROR CODES */
#define SOTP_ERR_NUM			7

/* I/O error */
#define SOTP_ERR_IO				1
/* Locking */
#define SOTP_ERR_LOCK			2
/* Database is not valid */
#define SOTP_ERR_INVALID_DB		3
/* Database is empty */
#define SOTP_ERR_EMPTY_DB		4
/* Seeking past last entry/before first entry/invalid seek */
#define SOTP_ERR_SEEK			5
/* Invalid arguments to function */
#define SOTP_ERR_ARGS			6
/* Unknown error */
#define SOTP_ERR_UNKNOWN		7


/* MACROS */
#define SOTP_ERROR( code, desc ) errstr=desc; sotp_errno = code
#define SOTP_ERROR_RET( code, desc ) errstr=desc; sotp_errno = code; return code

/* GLOBAL VARIABLES */

/*
 * Yes, we will be using global variables. A lot of better-written liraries use 
 * them, so bear with it ;-). Anyways, these are global because there is no 
 * other place to put them - sotpdb_t is not a good place, because it is 
 * DB specific (i.e.: there is no sotpdb_t handle on other modules)
 */
extern char *errstr;
extern int sotp_errno;

/* FUNCTION PROTOTYPES */
char *sotp_error_string( void );

#endif

