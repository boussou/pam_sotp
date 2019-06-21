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



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <security/pam_appl.h>
#include <pwd.h>

#include <libsotp.h>

#include "../config.h"
#include "otppasswd.h"
#include "readpass.h"

void print_usage( char *prgname ) {
	printf( "otppasswd v.%s  (C) 2004 Pedro Diaz (sotp@cavecanen.org)\n", CONFIG_SOTP_VERSION );
	printf( "\n" );
	printf( "Usage: %s [OPTIONS]\n", prgname );
	printf( "\n" );
	printf( "Available options:\n" );
	printf( "\n" );
	printf( "  -o file           File used to store the OTP list\n" );
	printf( "  -n number         Number of passwords to generate (default: 20)\n" );
	printf( "  -p prefix         Prefix to add in each generated password (default: No prefix)\n" );
	printf( "  -l length         Length of each generated password (default: 5)\n" );
	printf( "  -t lifespan       Built-in password lifespan, in seconds (default: 0)\n" );
	printf( "  -e days           Make the auth database expire in x days (default: don't expire)\n" );
	printf( "  -c charset        Charset used when generating passwords (default: 0123456789)\n" );
	printf( "  -d authdir        Authentication directory (default: %s)\n", CONFIG_AUTH_DIR_DEFAULT );
	printf( "  -P                Pretty-print the OTP list\n" );
	printf( "  -D                Disable the auth database\n" );
	printf( "  -E                Enable the auth database\n" );
	printf( "  -h                Show this help message\n" );
	printf( "\n" );
}



void init_options( otppasswd_options_t *opts ) {
	opts->prefs.pw_len = 5;
	opts->prefs.pw_charset = "0123456789";
	opts->prefs.pw_prefix = NULL;
	opts->prefs.pw_count = 20;
	opts->prefs.pw_lifespan = 0;
	opts->prefs.max_valid = 0; /* Forever */
	
	opts->output = stdout;
	opts->auth_dir = CONFIG_AUTH_DIR_DEFAULT;
	opts->pretty = 0;
	opts->op_mode = OPMODE_CREATE;
}	



short int parse_options( int argc, char **argv, otppasswd_options_t *opts ) {
	char c;
	short int cont=1;

	while (cont) {
		switch ( c=getopt( argc, argv, "o:t:n:p:l:c:e:d:hPED" ) ) {
			case 'o':
				opts->output = fopen( optarg, "w" );
				if (opts->output == NULL) {
					fprintf( stderr, "ERROR: Could not open %s for writing\n", optarg );
					return 0;
				}
				break;
			
			case 'n':
				opts->prefs.pw_count= atoi(optarg);
				if (opts->prefs.pw_count< 1) {
					fprintf( stderr, "ERROR: Minimum number of password entries is 1 (%d requested)\n",
							opts->prefs.pw_count);
					return 0;
				}
				break;


			case 'p':
				opts->prefs.pw_prefix = strdup( optarg );
				break;


			case 'l':
				opts->prefs.pw_len= atoi( optarg );
				break;

			case 'c':
				opts->prefs.pw_charset= strdup( optarg );
				if (strlen( opts->prefs.pw_charset) < 2) {
					fprintf( stderr, "ERROR: Password charset too short\n" );
					return 0;
				}
				break;

			case 't':
				opts->prefs.pw_lifespan = atoi( optarg );
				if (opts->prefs.pw_lifespan < 0) {
					fprintf( stderr, "ERROR: Invalid password lifespan (%d)\n", opts->prefs.pw_lifespan );
					return 0;
				}
				break;

			case 'e':
				opts->prefs.max_valid = atoi( optarg );
				if (opts->prefs.max_valid < 0) {
					fprintf( stderr, "ERROR: Invalid value for -e (%s)\n", optarg );
				}

				opts->prefs.max_valid *= 86400; /* 86400 seconds in a day */
				opts->prefs.max_valid += time( NULL ); 
				break;
			
			case 'd':
				opts->auth_dir = strdup( optarg );
				break;

			case 'h':
				return 0;
				break;

			case 'P':
				opts->pretty = 1;
				break;
				
			case 'E':
				opts->op_mode=  OPMODE_ENABLE;
				break;

			case 'D':
				opts->op_mode = OPMODE_DISABLE;
				break;

			case '?':
			case ':':
				return 0;
				break;
			case -1:
				cont = 0;
		}
	}

	return 1;
}

	
/* Conversation function for PAM */
int fconv( int num_msg, const struct pam_message **msg, struct pam_response  **resp, void *appdata_ptr ) {
	int i;
	char buffer[100];

	/* Allocate space for responses */
	*resp = (struct pam_response *) malloc( (size_t) sizeof(struct pam_response) * num_msg );
	
	for (i=0; i < num_msg; i++) {
	
		switch(msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			/* Get the password */
			readpass(buffer,sizeof(buffer),msg[i]->msg,READPASS_NOECHO);
				
			/* Return the password */
			resp[i]->resp = strdup( buffer );
			resp[i]->resp_retcode = 0; /* As stated in PAM's manual (apps) */
			break;			

		/* The following ones are easier */
		case PAM_PROMPT_ECHO_ON:
			readpass(buffer,sizeof(buffer),msg[i]->msg,READPASS_ECHO);

			/* Return */
			resp[i]->resp = strdup( buffer );
			resp[i]->resp_retcode = 0;
			break;			
			
		case PAM_ERROR_MSG:
			printf( "%s\n", msg[i]->msg );
			fflush( stdout );

			resp[i]->resp = NULL;
			resp[i]->resp_retcode = 0;
			break;
	
		case PAM_TEXT_INFO:
			fprintf( stderr, "%s\n", msg[i]->msg );

			resp[i]->resp = NULL;
			resp[i]->resp_retcode = 0;
			break;
		
		default:
			fprintf(stderr,"FATAL: invalid PAM message style");
			exit(1);
		}
	}
	return PAM_SUCCESS;
}

/* Gets the user name from the uid */
char *get_user( int uid ) {
	struct passwd *p;
	
	while ( (p=getpwent()) != NULL && p->pw_uid != uid);
	if (p==NULL)
		return NULL; /* strange, shouldn't happen... */

	return p->pw_name;
}




int create_db(  otppasswd_options_t *opts, char *user ) {
	char **otplist;
	sotpdb_t *handle;	
	int i;
	char buf[100];

	/* Build the path to the database */
	sprintf( buf, "%s/%s", opts->auth_dir, user );
	
	/* (Re)create the auth database */
	printf( "\nCreating the auth database (this could take a while)..." );
	if ( (handle=sotp_create_auth_db( buf, &opts->prefs, &otplist ))==NULL) {
		fprintf( stderr, "\nERROR: Could not create auth database in %s:%s\n", buf, sotp_error_string() );
		return 4;
	}
	
	/* Close the database */
	if (sotp_close_auth_db( handle ) != 0) {
		fprintf( stderr, "\nERROR: Could not close auth database: %s\n", sotp_error_string() );
		return 5;
	}
	printf( "ok\n" );

	/* Set the permissions */
	chmod( buf, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP );
	

	/* Output the clear text passwords */
	if (opts->output == stdout) 
		printf( "\n" );

	if (opts->pretty) {
		for (i=0; i < opts->prefs.pw_count; i++) {
			fprintf( opts->output, "[%02d] %s", i+1, otplist[i] );
			if (i % 4 == 3) 
				fprintf( opts->output, "\n" );
			else
				fprintf( opts->output,"      " );
		}
		fprintf( opts->output, "\n" );
	} else {
		for (i=0; i < opts->prefs.pw_count; i++) {
			fprintf( opts->output, "[%02d] %s\n", i+1, otplist[i] );
		}
	}

	/* Set the permissions of the OTP list file */
	fchmod( fileno(opts->output), S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP );
	
	/* Success */
	return 0;
}

int enable_disable_db( otppasswd_options_t *opts, char *user ) {
	sotpdb_t *handle;	
	sotpdb_cfg_t db_cfg;
	char buf[100];
	

	
	/* Build the path to the database */
	sprintf( buf, "%s/%s", opts->auth_dir, user );
	
	
	/* Open the database */
	if ( (handle=sotp_open_auth_db( buf ))==NULL) {
		fprintf( stderr, "\nERROR: Could not open auth database in %s:%s\n", buf, sotp_error_string() );
		return 4;
	}

	/* Get the database config */
	if ( sotp_db_get_config( handle, &db_cfg ) != 0 ) {
		fprintf( stderr, "\nERROR: Could not get DB config: %s\n", sotp_error_string() );
		return 5;
	}

	
	if (opts->op_mode == OPMODE_ENABLE) {
		db_cfg.flags = db_cfg.flags & (!SOTPDB_FL_DISABLED);
	} else {
		db_cfg.flags = db_cfg.flags | (SOTPDB_FL_DISABLED);
	}

	/* Set the database config */
	if ( sotp_db_set_config( handle, &db_cfg ) != 0) {
		fprintf( stderr, "\nERROR: Could not set DB config: %s\n", sotp_error_string() );
		return 6;
	}

	/* Close DB */
	if ( sotp_close_auth_db( handle ) != 0 ) {
		fprintf( stderr, "\nERROR: Could not close auth database in %s:%s\n", buf, sotp_error_string() );
		return 7;
	}

	return 0;
		

}
int main( int argc, char **argv ){
	char *user=NULL;
	otppasswd_options_t opts;
	pam_handle_t *ph;
	struct pam_conv pc;
	int retval;
		
	/* Sync output */
	setbuf( stdout, 0 );

	/* Set default options */
	init_options( &opts );
	
	
	/* Parse command line */
	if (!parse_options( argc, argv, &opts )) {
		print_usage( argv[0] );
		return 1;
	}

	/* Get the user */
	user = get_user( getuid() );

	/* If we are not root then request authentication using the otppasswd name */
	if (getuid() != 0) {

		/* Init pam */
		pc.conv = fconv;
		if (user == NULL ) {
			fprintf( stderr, "ERROR: Could not find user with getpwent()\n" );
			return 2;
		}
		if ( (retval=pam_start( "otppasswd", user, &pc, &ph )) != PAM_SUCCESS) {
			fprintf( stderr, "ERROR: Could not init PAM\n" );
		}
		
		/* Authenticate */
		if ((retval = pam_authenticate( ph, 0 )) != PAM_SUCCESS)  {
			fprintf( stderr, "ERROR: In pam_authenticate: %s\n", pam_strerror( ph, retval ) );
			return 3;
		}
		
		/* End PAM */
		pam_end( ph, PAM_SUCCESS );
	}


	/* Get perms */
	setregid( getegid(), -1 );


	/* Do something */
	if (opts.op_mode == OPMODE_CREATE) {
		/* Create an auth db */
		return create_db( &opts, user );
	} else {
		return enable_disable_db( &opts, user );
	}

}
