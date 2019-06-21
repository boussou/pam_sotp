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

#ifndef _OPTIONS_H_
#define _OPTIONS_H_


/* options.h: Options available for the module */


/* DATA STRUCTS */
typedef struct {
	char *auth_dir;                     /* Directory where the password files reside */
	unsigned int fail_delay;            /* Plan a delay after a failed auth          */
	
	/* Options related to the auth module */
	short int prompt_number;            /* Include password number in prompt         */
	int pw_lifespan;                    /* Lifespan for an used password, in seconds */
} pam_sotp_options_t;
	

/* FUNCTION PROTOTYPES */
void init_options( pam_sotp_options_t *opts );
void parse_options( int argc, const char **argv, pam_sotp_options_t *opts );

#endif

