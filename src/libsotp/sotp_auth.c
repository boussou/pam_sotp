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
#include <time.h>
#include <string.h>
#include <netinet/in.h>

#include "sotp_db.h"
#include "sotp_err.h"
#include "sha1.h"


/* IMPLEMENTATION */

int sotp_auth_entry( sotpdb_entry_t *entry, char *passwd, uint8_t *salt, int *res ) {
	char *salted_passwd;
	sha1_context ctx;
	uint8_t hashed_passwd[20];
	int pwlen= strlen(passwd);



	/* Check arguments */
	if (!entry) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid entry pointer" ) );
	} else if (!passwd) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid password" ) );
	} else if (!salt) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid salt" ) );
	} else if (!res) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid result pointer" ) );
	}
		

	/* Salt the password */
	salted_passwd = (char*) malloc( (size_t) pwlen + SOTPDB_SALT_SIZE );
	memcpy( salted_passwd, passwd, pwlen );
	memcpy( &salted_passwd[pwlen], salt, SOTPDB_SALT_SIZE );
	pwlen += SOTPDB_SALT_SIZE;

	/* Hash the password */
	sha1_starts( &ctx );
	sha1_update( &ctx, salted_passwd, pwlen );
	sha1_finish( &ctx, hashed_passwd );
	

	/* Compare */
	*res = memcmp( entry->hash, hashed_passwd, 20 )==0;

	return 0;
}

