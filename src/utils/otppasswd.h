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

#ifndef _OTPPASSWD_H_
#define _OTPPASSWD_H_

/* INCLUDES */
#include <stdio.h>

#include <libsotp.h>


/* DEFINES */
#define OPMODE_CREATE 1
#define OPMODE_DISABLE 2
#define OPMODE_ENABLE 3

/* DATA STRUCTS */
typedef struct {
	/* Generation options */
	sotp_gen_prefs_t prefs;
	
	/* Operation mode */
	int op_mode;      
	
	/* Other options */
	FILE *output;       /* Where to store the OTP list */
	char *auth_dir;     /* Authentication directory    */
	short int pretty;   /* Pretty-print                */
	
} otppasswd_options_t;



#endif 

