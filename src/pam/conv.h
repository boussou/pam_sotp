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

#ifndef _CONV_H_
#define _CONV_H_

/* INCLUDES */
#include <security/pam_modules.h>
#include <security/_pam_macros.h>

#include "options.h"

/* FUNCTION PROTOTYPES */
char *ask_password( pam_handle_t *pamh, pam_sotp_options_t *opts, int pnumber );
void write_msg( pam_handle_t *pamh, char *msgtext );

#endif 

