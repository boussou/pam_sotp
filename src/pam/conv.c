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


#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <string.h>

#include "options.h"

char *ask_password( pam_handle_t *pamh, pam_sotp_options_t *opts, int pnumber ) {	
	struct pam_conv *conv;
	int retval;
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *resp;
	char *password;
	char buffer[512];

	retval = pam_get_item(pamh, PAM_CONV, (const void**) &conv);
	if (retval != PAM_SUCCESS){
		return NULL;
	}


	msg.msg_style = PAM_PROMPT_ECHO_OFF;

	if (opts->prompt_number) {
		sprintf( buffer, "One time password [%02d]: ", pnumber );
		msg.msg = buffer;
	} else {
		msg.msg = "One time password: ";
	}

	msgp = &msg;
	retval= (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);

	if (resp == NULL) 
		return NULL;

	if (retval != PAM_SUCCESS) {
		free(resp->resp);
		free( resp );
		return NULL;
	}

	password = resp->resp;
	/*
	 * free( resp ); Okay, The PAM doc says I should free this, but I get free() errors
	 * if I do it. I guess it won't harm not free'ing it
	 */
	free( resp );
	return password;
}


int write_msg( pam_handle_t *pamh, char *msgtext ) {
	struct pam_conv *conv;
	int retval;
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *resp;

	retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
	if (retval != PAM_SUCCESS){
		return retval;
	}

	msg.msg_style = PAM_TEXT_INFO;
	msg.msg = msgtext;


	msgp = &msg;
	retval= (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);

	return retval;
}
