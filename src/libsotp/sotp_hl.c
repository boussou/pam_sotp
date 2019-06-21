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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>

#include "sotp_hl.h"
#include "sotp_db.h"
#include "sotp_auth.h"
#include "sotp_err.h"
#include "sha1.h"

#include "../config.h"


/* PRIVATE FUNCTIONS */
#ifdef CONFIG_RND_DEV
void read_rnd_buf( char *buf, int size, int fd ) { /* Don't complain, char* is necessary for addressing ;-) */
	int pos=0, res;

	while (size) {
		res = read( fd, &buf[pos], size );
		size = size -res;
		pos = pos+res;
	}
}
#endif

/* PUBLIC FUNCTIONS */

/* Provided just for completion */
sotpdb_t *sotp_open_auth_db( char *pathname ) {
	return sotp_db_open( pathname );
}


int sotp_close_auth_db( sotpdb_t *db ) {
	return sotp_db_close( db );
}


/* Pre-Authentication test: Decides if the database has at least one valid
 * password.
 *
 * Yes, this function is very similar to sotp_authenticate. Yes, this is intended.
 * No, merging both functions into one would not be a good idea ;-)
 *
 * Returns in *res:
 * 	1: Can authenticate (there are still valid passwords)
 * 	0: Can't authenticate (there is no single valid password with the provided lifespan)
 */
int sotp_can_authenticate( sotpdb_t *db, time_t pw_lifespan, int *res ) {
	int passwd_count, pointer, ret, i, cur_idx, final_lifespan;
	sotpdb_cfg_t db_config;
	sotpdb_entry_t pw_entry;
	time_t now;
	
	/* Check arguments */
	if (!db) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	} else if (pw_lifespan < 0) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid password lifespan" ) );
	} else if (!res) { 
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid result pointer" ) );
	}

	/* Get time */
	now = time( NULL );

	/* Get the number of passwords in the database and the pointer */
	if ( (ret=sotp_db_get_password_count( db, &passwd_count ))!=0) 
		return ret;
	
	if ( (ret=sotp_db_get_password_pointer( db, &pointer )) != 0) 
		return ret;
	
	/* Get the database configuration */
	if ((ret=sotp_db_get_config( db, &db_config ))!= 0) 
		return ret;

	/* Check if the database is disabled */
	if ( db_config.flags & SOTPDB_FL_DISABLED ) {
		/* Disabled db, can't auth */
		*res = 0;
		return 0;
	}
	
	/* Check if the database has at least one password */
	if (passwd_count==0) {
		/* Empty db, can't auth */
		*res = 0;
		return 0;
	}

	/* Now, check if there is at least one unused password */
	if ( (db_config.flags & SOTPDB_FL_EXHAUSTED) == 0) {
		/* At least one unused password, can auth */
		*res = 1;
		return 0;
	}
	
	/* Calculate the password lifespan as min(argument, header_lifespan) */
	final_lifespan = pw_lifespan < db_config.passwd_lifespan ? pw_lifespan : db_config.passwd_lifespan;


	/* Get the current entry index, to restore it later */
	if ( (ret=sotp_db_get_entry_idx( db, &cur_idx ))!=0) 
		return ret;
	
	
	/* If we get here it means that the database is exhausted. Check for
	 * older passwords 
	 */
	if ( (ret=sotp_db_seek_entry( db, 0 )) !=0) 
		return ret;

	*res = 0;
	for (i=0; i < passwd_count; i++) {
		
		/* Get the current entry */
		if ( (ret=sotp_db_get_entry( db, &pw_entry ))!=0) 
			return ret;

		/* See if it is still valid */
		if (pw_entry.stamp + final_lifespan >= now) {
			/* Valid, can authenticate */
			*res = 1; 
			break;
		}
		
		/* Advance one entry */
		if ((ret=sotp_db_next_entry( db ))!=0)
			return ret;

		
	}

	/* Restore the entry index */
	if ( (ret=sotp_db_seek_entry( db, cur_idx )) !=0) 
		return ret;

	/* Success */
	return 0;
}



/* Authenticates an user */
/* 
 * Returns in *res:
 * 		 2: Auth is OK, used an older password
 * 		 1: Auth is OK, used current password 
 * 		 0: Auth failed, passwords do not match (older and current)
 * 		-1: Auth failed, older passwords do not match and no current password 
 * 		-2: Auth failed, database disabled (unless forced)
 * 		-3: Auth failed, database expired (unless forced)
 *
 * Older passwords are only checked if their lifespan is still valid
 */
int sotp_authenticate( char *password, sotpdb_t *db, time_t pw_lifespan, short int force, int *res ) {
	int final_lifespan, cur_entry, i, ret, tmp;
	time_t now, created;
	sotpdb_entry_t pw_entry;
	sotpdb_cfg_t db_config;
	

	/* Check arguments */
	if (!db) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	} else if (!password) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid password" ) );
	} else if (pw_lifespan < 0) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid password lifespan" ) );
	} else if (!res) { 
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid result pointer" ) );
	}


	/* Get the database configuration */
	if ((ret=sotp_db_get_config( db, &db_config ))!= 0) 
		return ret;

	
	/* Get the time */
	now = time( NULL );
	

	/* Check if the database is disabled */
	if (!force && (db_config.flags & SOTPDB_FL_DISABLED)) {
		*res = -2;
		return 0;
	}

	/* Check if the database is expired */
	if ((ret=sotp_db_get_creation_time( db,  &created ))!=0) 
		return ret;

	if (!force && db_config.max_valid && (created + db_config.max_valid < now)) {
		*res =-3;
		return 0;
	}
	
	/* Calculate the password lifespan as min(argument, header_lifespan) */
	final_lifespan = pw_lifespan < db_config.passwd_lifespan ? pw_lifespan : db_config.passwd_lifespan;

	/* Check for validity of older passwords, but only if the lifespan is positive */

	if (final_lifespan > 0) {
		if ((ret=sotp_db_get_entry_idx( db, &cur_entry ))!=0)
			return ret;
		
		/* Start with the oldest password */
		if ( (ret=sotp_db_seek_entry( db, 0 )) != 0) 
			return ret;
		
		/* 
		 * We iterate until before the current entry. If the database is "exhausted", we iterate
		 * until the current entry 
		 */
		if ( db_config.flags & SOTPDB_FL_EXHAUSTED ) 
			cur_entry++;

		for (i=0; i < cur_entry; i++) {
			/* Get the current entry */
			if ( (ret=sotp_db_get_entry( db, &pw_entry ))!=0)
				return ret;

			/* See if it is still valid */
			if ((ret=sotp_auth_entry( &pw_entry, password, db_config.salt, &tmp ))!=0)
				return ret;
			
			if (pw_entry.stamp + final_lifespan >= now && tmp) {
				/* Valid and authentication is successful */
				*res = 2; 

				return 0;
			}

			/* Advance one entry */
			if ((ret=sotp_db_next_entry( db ))!=0)
				return ret;
		}

	}
	
	/* Check again if the database is "exhausted". If yes -> *res == -1 */
	if (db_config.flags & SOTPDB_FL_EXHAUSTED ) {
		*res = -1;
		return 0;
	}
	
	/* Check the password pointer */
	ret = sotp_db_get_entry( db, &pw_entry );
	switch (ret) {
		case SOTP_ERR_EMPTY_DB:
			/* Database empty */
			*res=-1;
			return 0;
		
		case 0:
			/* OK */
			break;
		
		default:
			/* Some other error */
			return ret;
	}
	
	if ((ret=sotp_auth_entry( &pw_entry, password, db_config.salt, &tmp))!=0)
		return ret;
	
	if (tmp) {
		/* Set the stamp for the current entry */
		pw_entry.stamp = now;
		
		if ((ret=sotp_db_write_entry( db, &pw_entry ))!=0)
			return ret;

		/* Advance the password pointer in the database */
		if ((ret=sotp_db_auth_ok( db ))!=0)
			return ret;

		/* Return - success */
		*res = 1;

	} else {
		/* Auth failed */
		sotp_db_auth_failed( db );
		*res = 0;
	}

	/* Success */
	return 0;
	
}

/* Creates an auth database */
sotpdb_t *sotp_create_auth_db( const char *path, sotp_gen_prefs_t *prefs, char ***otplist ){
	sotpdb_t *h;
	sotpdb_cfg_t db_cfg;
	sotpdb_entry_t entry;
	int i, j, charset_len, gentop;
	unsigned int pos;
	char *buffer;
	sha1_context ctx;
	
#ifdef CONFIG_RND_DEV
	int rnd_fd;
#endif

	/* Set the database config */
	db_cfg.flags = 0;
	db_cfg.passwd_lifespan = prefs->pw_lifespan;
	db_cfg.max_valid = prefs->max_valid;

	/* The salt */
#ifdef CONFIG_RND_DEV

	/* Open the random device */
	rnd_fd = open( CONFIG_RND_DEV, O_RDONLY );
	if (rnd_fd == -1) {
		/* Cannot open device */
		return NULL;
	}
	
	/* Fill the salt buffer */
	read_rnd_buf( db_cfg.salt, SOTPDB_SALT_SIZE, rnd_fd );

	
#else 
	/* Seed the random number generator */
	srandom( time( NULL ) ^ getpid() );
	for (i=0; i < SOTPDB_SALT_SIZE; i++) 
		db_cfg.salt[i] = random()% 256;
#endif
	
	/* Create an empty database */
	h = sotp_db_create( path, &db_cfg );
	if (h == NULL) {
		/* Could not create the database */
		return NULL;
	}

	/* Allocate space for an array of chars* (otplist) */
	*otplist = (char **) malloc( (size_t) sizeof(char*)*prefs->pw_count );

	/* Put default chars for password, if needed */
	if (prefs->pw_charset== NULL) {
		prefs->pw_charset= "ABCDEFGHIJKLMNPQRSTUVWXYabcdefghijmnopqrstuvwxyz0123456789";
	}
	charset_len = strlen( prefs->pw_charset );

	/* Prepare the password buffer */
	if (prefs->pw_prefix != NULL) {
		buffer = (char *) malloc( (size_t) strlen(prefs->pw_prefix) + prefs->pw_len+1 );
		strcpy( buffer, prefs->pw_prefix );
		gentop = strlen(prefs->pw_prefix) + prefs->pw_len;
	} else {
		buffer = (char *) malloc( (size_t) prefs->pw_len +1 );
		gentop = prefs->pw_len;
	}
	
	/* Add entries */
	for (i=0; i < prefs->pw_count; i++) {
		
		if (prefs->pw_prefix != NULL) 
			j = strlen(prefs->pw_prefix);
		else
			j = 0;
					
		/* Loop for generating the password */
		for (; j < gentop; j++) {
			/* Generate a position in the charset */
#ifdef CONFIG_RND_DEV 
			read_rnd_buf( (char*)&pos, sizeof(int), rnd_fd );
			pos = pos % charset_len;
#else
			pos = random() % charset_len;
#endif

			/* Add the char to the password */
			buffer[j] = prefs->pw_charset[pos];
		}

		/* Terminate the entry */
		buffer[j] = '\0';
	
		/* Hash the password */
		sha1_starts( &ctx );
		sha1_update( &ctx, buffer, strlen(buffer) );
		sha1_update( &ctx, db_cfg.salt, SOTPDB_SALT_SIZE );
		sha1_finish( &ctx, entry.hash );

	

		
		/* Set the timestamp to zero (not used)*/
		entry.stamp = 0;

		
		/* Write the entry */
		sotp_db_add_entry( h, &entry );

		/* Copy the password to the array */
		if (prefs->pw_prefix != NULL) {
			(*otplist)[i] = strdup( &buffer[strlen(prefs->pw_prefix)] );
		} else{
			(*otplist)[i] = strdup( buffer );
		}
	}
	

	/* Set the current entry to the first one (it shoulnd't be necessary, just in case) */
	sotp_db_seek_entry( h, 0 );
	
	/* Return the handle */
	return h;
	
}



