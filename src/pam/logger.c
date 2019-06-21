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


/*
 * logger.c: Implementation of the logging wrapper 
 *
 * From now, this is only a wrapper to syslog(3), but sometime we
 * might want to add fancy features here
 *
 * Choice of log levels according to: 
 * http://www.kernel.org/pub/linux/libs/pam/Linux-PAM-html/pam_modules-5.html#ss5.1
 */




/* INCLUDES */
#include <syslog.h>
#include <stdio.h>
#include <string.h>

#include "logger.h"
#include "../config.h"


void log_auth_error( const char *user ) {
	syslog( LOG_AUTHPRIV | LOG_NOTICE, "(pam_sotp) Failed login for user %s", user );
}
void log_config_error( const char *msg ) {
	syslog( LOG_AUTHPRIV | LOG_ERR, "(pam_sotp) Error in configuration: %s", msg );
}

void log_module_error( const char *msg, short int critical ) {
	
	if (critical) {
		syslog( LOG_AUTHPRIV | LOG_CRIT, "(pam_sotp) Critical error: %s", msg );
	} else {
		syslog( LOG_AUTHPRIV | LOG_ALERT, "(pam_sotp) Error: %s", msg );
	}
}

void log_debug( const char *msg ) {

#ifdef CONFIG_DEBUG
	syslog( LOG_AUTHPRIV | LOG_DEBUG, "(pam_sotp) Debug: %s", msg );
#endif 


}

