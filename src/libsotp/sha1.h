/*
 *  FIPS-180-1 compliant SHA-1 implementation
 *
 *  Copyright (C) 2001-2003  Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */



#ifndef _SHA1_H
#define _SHA1_H

/* INCLUDES */
#include <netinet/in.h>


/* DATA STRUCT */
typedef struct
{
	uint32_t total[2];
	uint32_t state[5];
	uint8_t buffer[64];
} sha1_context;

void sha1_starts( sha1_context *ctx );
void sha1_update( sha1_context *ctx, uint8_t *input, uint32_t length );
void sha1_finish( sha1_context *ctx, uint8_t digest[20] );

#endif /* sha1.h */
