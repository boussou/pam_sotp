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

#ifndef _SOTP_HL_H_
#define _SOTP_HL_H_



/* INCLUDES */
#include <netinet/in.h>

#include "sotp_db.h"



/* DATA TYPES */
typedef struct {

	/* Generation options */
	int pw_len;
	char *pw_charset;
	char *pw_prefix;
	int pw_count;
	int hash_type; /* Ignored for now */

	/* Other options for the database */
	uint32_t pw_lifespan; /* Builtin password lifespan */
	uint32_t max_valid;   /* Max valid time            */

} sotp_gen_prefs_t;


/* FUNCTION PROTOTYPES */
sotpdb_t *sotp_open_auth_db( char *pathname );
int sotp_close_auth_db( sotpdb_t *db );
sotpdb_t *sotp_create_auth_db( const char *path, sotp_gen_prefs_t *prefs, char ***otplist );
int sotp_can_authenticate( sotpdb_t *db, time_t pw_lifespan, int *res );
int sotp_authenticate( char *password, sotpdb_t *db, time_t pw_lifespan, short int force, int *res );
#endif

