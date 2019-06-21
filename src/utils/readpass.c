/******************************************************************************
 * ReadPass: a better getpass()                                               *
 *                                                                            *
 * Copyright (C) 2004 Jose Luis Tallon <jltallon@adv-solutions.net>           *
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
 * This module provides a "modern" implementation of getpass
 */

#include <stdio.h>
#include <termios.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define RET_SUCCESS	0
#define RET_ERROR	-1


/* forward decl */
int readpass(char *buffer, unsigned maxlen, const char *prompt, int disable_echo);


/* couple globals, to keep state */
static struct termios __attr;
static int __nTtyFD = -1;


static int __disable_echo(void)
{
 struct termios attr;
 
	/* save context */
	memcpy( &attr, &__attr, sizeof(struct termios));
	
	attr.c_lflag = attr.c_lflag & ~ECHO;
	if( tcsetattr(__nTtyFD, TCSANOW,  &attr) == -1) {
		perror( "tcsetattr() [unset echo]" );
		return RET_ERROR;
	}
	return RET_SUCCESS;
}

static int __restore_attr()
{
	
	if( __nTtyFD != -1 && tcsetattr(__nTtyFD, TCSANOW,  &__attr) == -1) {
		perror( "tcsetattr() [restore]" );
		return RET_ERROR;
	}
	return RET_SUCCESS;
}




int readpass(char *buffer, unsigned maxlen, const char *prompt, int disable_echo)
{
 void (*pfnINThandler)(int);
 void (*pfnTERMhandler)(int);
 char *ptr;
 
	/* Display the prompt */
	fputs(prompt, stdout);
	fflush(stdout);

	/* open TTY and save context */
	if( !isatty(STDIN_FILENO) ){
		__nTtyFD = open( "/dev/tty", O_RDONLY );
	}
	else __nTtyFD=dup(STDIN_FILENO);
	
	if( tcgetattr(__nTtyFD, &__attr) == -1) {
		perror( "tcgetattr()" );
		return RET_ERROR;
	}

	/* Guard against nervous users who press Ctrl+C ... */
	pfnINThandler=signal(SIGINT, SIG_IGN );
	pfnTERMhandler=signal(SIGTERM, SIG_IGN );

	/* disable echo*/
	if( disable_echo ) {
		if( __disable_echo() < 0 )
			return RET_ERROR;
	}

	/* READ PASSWORD and 'beautify' it*/
	fgets(buffer, maxlen, stdin);
	if( (ptr=strchr(buffer,'\n')) != NULL )*ptr='\0';

	if( disable_echo ) {
		fputs("\n",stdout); 
		fflush(stdout);
	}
	
	/* restore settings */
	__restore_attr();
	
	close(__nTtyFD);
	
	return RET_SUCCESS;
}
