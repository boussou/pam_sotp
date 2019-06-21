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
 
/* sotp_db.h: Definition of the SOTP DB API */

#ifndef _SOTP_DB_H_
#define _SOTP_DB_H_


/* INCLUDES */
#include <netinet/in.h>
#include <time.h>

/* DEFINES */
#define SOTPDB_MAGIC		"!#SOTP#"
#define SOTPDB_MAGIC_SIZE	7
#define SOTPDB_VERSION		0x10
#define SOTPDB_SALT_SIZE	4
#define SOTPDB_HASHID_SHA1	1



/* Database flags */
#define SOTPDB_FL_DISABLED		0x00000001
#define SOTPDB_FL_RESTRICTED	0x00000002
#define SOTPDB_FL_EXHAUSTED		0x00000004


/* DATA TYPES */

/* DB lead */
typedef struct {
	char 		magic[SOTPDB_MAGIC_SIZE]	__attribute__((__packed__));
	uint8_t	    version	__attribute__((__packed__));
}sotpdb_lead_t ;	


/* Configuration values */
typedef struct {
	uint32_t	flags	__attribute__((__packed__));                 /* database flags                  */
	uint32_t	min_valid	__attribute__((__packed__));             /* min passwd db validity          */
	uint32_t	max_valid	__attribute__((__packed__));             /* max passwd db validity          */
	uint32_t	passwd_lifespan	__attribute__((__packed__));         /* Password lifespan               */

	uint8_t 	hash_type	__attribute__((__packed__));             /* Hash used for this DB           */
	uint8_t		salt[SOTPDB_SALT_SIZE]	__attribute__((__packed__)); /* Salt for hashing                */

	/* Reserved fields for future use */
	uint8_t		resv[64]	__attribute__((__packed__));

} sotpdb_cfg_t; 

/* DB header */
typedef struct {
	/* DB lead */
	sotpdb_lead_t lead	__attribute__((__packed__));
	
	/* DB configuration */
	sotpdb_cfg_t conf	__attribute__((__packed__));
	
	/* When it was generated */
	uint32_t	gen_time	__attribute__((__packed__)); 


	/* Number of passwords in the database */
	uint32_t passwd_count	__attribute__((__packed__));

	/* Number of authentication errors with the current password pointer */
	uint32_t auth_errors	__attribute__((__packed__));

	/* Pointer to the current password */
	uint32_t passwd_pointer	__attribute__((__packed__));


} sotpdb_header_t;


/* One password entry */
typedef struct {
	/* Time stamp of when the password was used */
	uint32_t stamp	__attribute__((__packed__));
	
	/* Hash of the password: SHA1 - 160 bits  - 20 bytes*/
	uint8_t hash[20]	__attribute__((__packed__));
} sotpdb_entry_t ;



/* Handle - Forward declaration */
struct sotpdb_handle; 
typedef struct sotpdb_handle sotpdb_t;


/* FUNCTION PROTOTYPES */

/* Open database */
sotpdb_t *sotp_db_open( const char *path );

/* Create database */
sotpdb_t *sotp_db_create( const char *path, sotpdb_cfg_t *cfg  );

/* Close database */
int	sotp_db_close( sotpdb_t *handle );

/* Advance one entry */
int sotp_db_next_entry( sotpdb_t *handle );

/* Back one entry */
int sotp_db_prev_entry( sotpdb_t *handle );

/* Get the current entry */
int sotp_db_get_entry( sotpdb_t *handle, sotpdb_entry_t *entry );

/* Seek to an specified entry */
int sotp_db_seek_entry( sotpdb_t *handle, unsigned int idx );

/* Get current entry index */
int sotp_db_get_entry_idx( sotpdb_t *handle, int *idx );

/* Add an entry */
int sotp_db_add_entry( sotpdb_t *handle, sotpdb_entry_t *entry );

/* Write an entry */
int sotp_db_write_entry( sotpdb_t *handle, sotpdb_entry_t *entry );

/* Write the header to the file */
int sotp_db_write_header( sotpdb_t *handle );

/* Get & set the configuration */
int sotp_db_get_config( sotpdb_t *handle, sotpdb_cfg_t *cfg );
int sotp_db_set_config( sotpdb_t *handle, const sotpdb_cfg_t *cfg );

/* Advance the password pointer */
int sotp_db_auth_ok( sotpdb_t *handle );

/* Increment the number of auth errors */
int sotp_db_auth_failed( sotpdb_t *handle );

/* Get the number of auth errors with the current password pointer */
int sotp_db_get_auth_errors( sotpdb_t *handle, int *nerrors );

/* Get the creation time of the database */
int sotp_db_get_creation_time( sotpdb_t *handle, time_t *when );

/* Gets the number of passwords in a database */
int sotp_db_get_password_count( sotpdb_t *handle, int *npasswords );

/* Gets the password pointer of the database */
int sotp_db_get_password_pointer( sotpdb_t *handle, int *pointer );

#endif	
