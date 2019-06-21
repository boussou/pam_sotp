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

#include "logger.h"
#include "options.h"
#include "../config.h"


void init_options( pam_sotp_options_t *opts ) {
	opts->auth_dir = CONFIG_AUTH_DIR_DEFAULT;
	opts->fail_delay = 0;
	
	opts->prompt_number = 1;
	opts->pw_lifespan = 0;
}

void parse_options( int argc, const char **argv, pam_sotp_options_t *opts ) {
	int i;
	char option[30], value[80];
	char buffer[100];

	for (i=0; i < argc; i++) {
		
		if (sscanf( argv[i], "%[^=]=%s", option, value ) == 2)  {

			if (strcmp( option, "auth_dir" )==0) {
				opts->auth_dir = strdup( value );
			
			} else if (strcmp( option, "fail_delay" ) == 0) {
				opts->fail_delay = atoi( value );
		
			} else if (strcmp( option, "prompt_number" )==0) {
				if (strcmp( value, "yes" )==0) {
					opts->prompt_number = 1;
				} else if (strcmp( value, "no" )==0) {
					opts->prompt_number = 0;
				}
			
			} else if (strcmp( option, "pw_lifespan" )==0) {
				opts->pw_lifespan = atoi( value );
		
			
			} else {
				if (strlen(argv[i]) > 80)  {
					strcpy( buffer, "Unknown argument (too long!)" );
				} else {
					sprintf( buffer, "Unknown argument '%s'", argv[i] );
				}
				log_config_error( buffer );
			}
				
				
		}
	}

}


