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


/* INCLUDES & DEFINES */
#define DEFAULT_USER "nobody"
#define PAM_SM_AUTH
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <string.h>
#include <errno.h>

#include <libsotp.h>

#include "pam_sotp.h"
#include "options.h"
#include "conv.h"
#include "logger.h"

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc ,const char **argv) {
	int retval, userlen, res;
	const char *user=NULL;
	char *password;
	char buffer[512];
	gid_t old_gid;
	uid_t old_uid;
	pam_sotp_options_t opts;
	sotpdb_t *dbh; 


	log_debug( "Starting pam_sm_authenticate()" );
	

	/* jump to the correct uid and gid */
	old_gid = getgid();
	old_uid = getuid();

	setregid( getegid(),-1 );
	setreuid( geteuid(), -1 );	
	
	
	/* Get the user */
	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS) {
		RETGUID( old_uid, old_gid, retval );
	}
	
	if (user == NULL || *user == '\0') {
		retval = pam_set_item(pamh, PAM_USER, (const void *) DEFAULT_USER);
		if (retval != PAM_SUCCESS) {
			log_debug( "Could not determine user" );
			RETGUID( old_uid,  old_gid, PAM_USER_UNKNOWN );
		}
		
	}

	/* Init & parse options */
	init_options( &opts );
	parse_options( argc, argv, &opts );


	/* Check if the user has an OTP database */
	userlen = strlen( user );
	if (userlen + strlen(opts.auth_dir) > 509 || userlen > 450 ) {
		char *tmp;

		tmp = strdup(user);
		tmp[450] = '.';
		tmp[451] = '.';
		tmp[452] = '.';
		tmp[453] = '\0';

		sprintf( buffer, "User name too large: %s", tmp );
		log_module_error( buffer, 0 );
		free( tmp );

		RETGUID( old_uid,  old_gid, PAM_TRY_AGAIN ); /* Too large! */
	}
	

	sprintf( buffer, "Authenticating user %s", user );
	log_debug( buffer );

	
	sprintf( buffer, "%s/%s", opts.auth_dir, user );
	if (access( buffer, R_OK | W_OK ) !=0 )  {
		/* The user has not an OTP database */
		
		sprintf( buffer, "User %s does not have an OTP database", user );
		log_module_error( buffer, 0 );
		RETGUID( old_uid,  old_gid, PAM_USER_UNKNOWN );
	}
	
	/* Read the OTP database */
	if ((dbh = sotp_open_auth_db( buffer )) == NULL) {
		/* For some reason we can't read the password file */
		sprintf( buffer, "sotp_open_auth_db() failed: %s", sotp_error_string() );
		log_debug( buffer );
		RETGUID( old_uid,  old_gid, PAM_AUTHINFO_UNAVAIL );
	}


	/* Check if we can authenticate - if not, return with AUTHINFO_UNAVAIL */
	if ( (retval = sotp_can_authenticate( dbh, opts.pw_lifespan, &res ))!= 0) {
		/* For some reason this function failed */
		sprintf( buffer, "sotp_can_authenticate() failed: %s", sotp_error_string() );
		log_debug( buffer );
		RETGUID( old_uid,  old_gid, PAM_AUTHINFO_UNAVAIL );
	}
	
	if (!res) {
		/* We can't authenticate */

		/* Log */
		sprintf( buffer, "The user %s could not be authenticated - no valid passwords found", user );
		log_module_error( buffer, 0 );
		log_debug( buffer );

		/* Close the database */
		sotp_close_auth_db( dbh ); 

		/* Return */
		RETGUID( old_uid,  old_gid, PAM_AUTHINFO_UNAVAIL );

	}

	/* Check if there is already an auth token */
	retval = pam_get_item( pamh, PAM_AUTHTOK, (const void**) &password );

	
	if (retval != PAM_SUCCESS || password == NULL) {
		int tmp;
	
	
		sotp_db_get_entry_idx( dbh, &tmp );
		sotp_close_auth_db( dbh ); /* We don't want to lock the db when asking a pw */
		
		/* Ask for the password */
		log_debug( "Asking for password..." );
		password = ask_password( pamh, &opts, tmp +1 ); /* in conv.c */

		/* Set the auth token */
		log_debug( "Got password!" );
		pam_set_item( pamh, PAM_AUTHTOK, password );

		/* Reopen the database */
		if ((dbh = sotp_open_auth_db( buffer )) == NULL) {
			/* For some reason we can't read the password file */
			sprintf( buffer, "sotp_open_auth_db() failed: %s", sotp_error_string() );
			log_debug( buffer );
			RETGUID( old_uid,  old_gid, PAM_AUTHINFO_UNAVAIL );
		}


	}
	
	
	
	/* Check password */
	retval = sotp_authenticate( password, dbh, opts.pw_lifespan, 0, &res );
	if (retval !=0) {
		RETGUID( old_uid,  old_gid, PAM_AUTHINFO_UNAVAIL );
	}
	switch (res) {
			
			/* Authentication OK */
		case 2:
			log_debug( "Authentication used an older password" );
		case 1:
			log_debug( "Authentication successful" );
			
			/* Close the password db */
			if (sotp_close_auth_db( dbh )!=0) {
				/* Error closing the password db */
				sprintf( buffer, "sotp_close_auth_db() failed: %s", sotp_error_string() );
				log_module_error( buffer, 1 );
				RETGUID( old_uid,  old_gid, PAM_AUTHINFO_UNAVAIL );
			}
			RETGUID( old_uid,  old_gid, PAM_SUCCESS );
			break;
			

		
		case 0:
			log_debug( "Auth failed: passwords do not match" );
			break;
		
		case -1:
			log_debug( "Auth failed: Password database exhausted, older passwords do not match" );
			write_msg( pamh, "Password database exausted, older passwords do not match" );
			break;
		
		case -2:
			log_debug( "Auth failed: Database disabled" );
			write_msg( pamh, "Password database disabled" );
			break;

		case -3:
			log_debug( "Auth failed: Database expired" );
			write_msg( pamh, "Password database expired" );
			break;
	}
	/* Authentication failed */
	log_auth_error( user );
			
#ifdef PAM_FAIL_DELAY
	/* Plan a delay (0 by default) */
	sprintf( buffer, "Planning a min. delay of %d seconds", opts.fail_delay );
	log_debug( buffer );
	pam_fail_delay( pamh, opts.fail_delay * 1000000 );
#endif 
	

	/* Close password file */
	sotp_db_close( dbh );


	log_debug( "Ending pam_sm_authenticate()" );
	
	/* Change to the correct GID and return */
	RETGUID( old_uid,  old_gid, PAM_AUTH_ERR );

	
}


PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc ,const char **argv) {
	return PAM_SUCCESS;
}


/* Static module stuff */

#ifdef PAM_STATIC 

struct pam_module _pam_sotp_modstruct = {       /* static module data */
     "pam_sotp",
     NULL,
     NULL,
     NULL,
     NULL,
     NULL,
     pam_sm_chauthtok,
};

#endif 
