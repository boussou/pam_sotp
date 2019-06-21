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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <time.h>
#include <errno.h>

#include "sotp_db.h"
#include "sotp_err.h"

#include "../config.h"




/* PRIVATE DATA TYPES */
struct sotpdb_handle{
	int              fd;         /* File descriptor            */
	int              cur_entry;  /* Index of the current entry */
	sotpdb_header_t  header;     /* DB header                  */
};


/* PRIVATE FUNCTIONS */

/* Converts config values to Host Byte Order */
void config2hbo( sotpdb_cfg_t  *conf ) {
	conf->flags = ntohl( conf->flags );
	conf->min_valid = ntohl( conf->min_valid );
	conf->max_valid = ntohl( conf->max_valid );
	conf->passwd_lifespan = ntohl( conf->passwd_lifespan );
}

/* Converts header values to Host Byte Order */
void header2hbo( sotpdb_header_t *h ) {
	
	/* The lead is endianess-independent */

	/* The config section */
	config2hbo( &h->conf );
	
	/* Counters and pointers */
	h->gen_time = ntohl( h->gen_time );
	h->passwd_count = ntohl( h->passwd_count );
	h->auth_errors = ntohl( h->auth_errors );
	h->passwd_pointer = ntohl( h->passwd_pointer );
}

/* Converts config values to Network Byte Order */
void config2nbo( sotpdb_cfg_t *conf ) {
	conf->flags = htonl( conf->flags );
	conf->min_valid = htonl( conf->min_valid );
	conf->max_valid = htonl( conf->max_valid );
	conf->passwd_lifespan = htonl( conf->passwd_lifespan );
}


/* Converts header values to Network Byte Order */
void header2nbo( sotpdb_header_t *h ) {
	
	/* The lead is endianess-independent */

	/* The config section */
	config2nbo( &h->conf );

	/* Counters and pointers */
	h->gen_time = htonl( h->gen_time );
	h->passwd_count = htonl( h->passwd_count );
	h->auth_errors = htonl( h->auth_errors );
	h->passwd_pointer = htonl( h->passwd_pointer );
}



/* PUBLIC INTERFACE */


/* Open a database */
sotpdb_t *sotp_db_open( const char *path ){
	struct sotpdb_handle *handle = (struct sotpdb_handle*) malloc( (size_t) sizeof(struct sotpdb_handle) );
	char errbuf[100];
	int ret;

	/* Check arguments */
	if (!path) {
		SOTP_ERROR( SOTP_ERR_ARGS, strdup( "Null path" ) );
		return NULL;
	}
	
	/* Open the file */
	handle->fd = open( path, O_RDWR );
	if (handle->fd == -1) {
		/* Cannot open */
		sprintf( errbuf, "Cannot open %s (%s)", path, strerror(errno) );
		SOTP_ERROR( SOTP_ERR_IO,  strdup(errbuf) );
		return NULL;
	}


	/* First of all, lock the database */
	if (lockf( handle->fd, F_LOCK, 0 ) == -1)  {
		/* Cannot lock */
		close( handle->fd );

		sprintf( errbuf, "Cannot lock %s (%s)", path, strerror(errno) );
		SOTP_ERROR( SOTP_ERR_LOCK, strdup(errbuf) );
		return NULL;
	}
	
	
	/*
	 * Some sanity checks. Note that there is no point of placing these on separate
	 * functions; we only need them here 
	 */
	
	/* Read the header */
	if (read( handle->fd, &handle->header, sizeof(sotpdb_header_t) ) != sizeof(sotpdb_header_t) ) {
		/* Corrupted file */
		close( handle->fd );

		SOTP_ERROR( SOTP_ERR_INVALID_DB, NULL );
		return NULL;
	}

	/* Convert the header to host byte order */
	header2hbo( &handle->header );
	
	/* Check the signature */
	if (memcmp( handle->header.lead.magic, SOTPDB_MAGIC, SOTPDB_MAGIC_SIZE ) != 0) {
		/* Invalid magic */
		close( handle->fd );

		SOTP_ERROR( SOTP_ERR_INVALID_DB, strdup( "Invalid magic" ) );
		return NULL;
	}

	/* 
	 * Check version: Since this is the first release of sotpdb backward compat.
	 * is not an issue. We simply refuse to read any other DB version than SOTPDB_VERSION
	 */
	if (handle->header.lead.version != SOTPDB_VERSION)  {
		/* Invalid version */
		close( handle->fd );

		sprintf( errbuf, "Invalid DB version: %02X", handle->header.lead.version ) ;
		SOTP_ERROR( SOTP_ERR_INVALID_DB, strdup( errbuf ) );
		return NULL;
	}
	

	
	/* Seek to the current password entry */
	if ( (ret=sotp_db_seek_entry( handle, handle->header.passwd_pointer ))!=0) {
		return NULL;
	}

	/* Return the handle */
	return handle;
}

/* Create an empty database */
sotpdb_t *sotp_db_create( const char *path, sotpdb_cfg_t *cfg  ) {
	struct sotpdb_handle *handle = (struct sotpdb_handle*) malloc( (size_t) sizeof(struct sotpdb_handle) );
	int i;
	char errbuf[100];

	/* Check arguments */
	
	if (!path) {
		SOTP_ERROR( SOTP_ERR_ARGS, strdup( "Null path" ) );
		return NULL;
	} else if (!cfg) {
		SOTP_ERROR( SOTP_ERR_ARGS, strdup( "Null config" ) );
		return NULL;
	}


	
	/* Create the file */
	handle->fd = open( path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR );
	if (handle->fd == -1) {
		/* Cannot create */
		sprintf( errbuf, "Cannot create database file (%s)", strerror( errno ) );
		SOTP_ERROR( SOTP_ERR_IO, strdup( errbuf ) );
		return NULL;
	}

	/* Lock the database */
	if (lockf( handle->fd, F_LOCK, 0 ) == -1)  {
		/* Cannot lock */
		close( handle->fd );
		
		sprintf( errbuf, "Cannot lock %s (%s)", path, strerror(errno) );
		SOTP_ERROR( SOTP_ERR_LOCK, strdup(errbuf) );
		return NULL;
	}

	/* Create the header */
	memcpy( handle->header.lead.magic, SOTPDB_MAGIC, SOTPDB_MAGIC_SIZE );
	handle->header.lead.version = SOTPDB_VERSION;

	memcpy( &handle->header.conf, cfg, sizeof(sotpdb_cfg_t) );

	handle->header.gen_time = (uint32_t) time(NULL);
	handle->header.passwd_count = 0;
	handle->header.passwd_pointer = 0;
	handle->header.auth_errors = 0;
	
	
	/* Overwrite some values of the header that are simply not supported in this version */
	handle->header.conf.hash_type = SOTPDB_HASHID_SHA1;
	
	
	for (i=0; i < 64; i++) 
		handle->header.conf.resv[i] = 0xAA;
	
	/* Write the header on disk */
	handle->cur_entry = 0;
	sotp_db_write_header( handle );
	
	return handle;
}

/* Close the database */
int sotp_db_close( sotpdb_t *handle){
	int ret;
	char errbuf[100];

	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	}

	/* Write the header and close the file descriptor*/
	if ( (ret=sotp_db_write_header( handle ))!=0) {
		return ret;
	}
	
	if (close( handle->fd ) != 0) {
		sprintf( errbuf, "Cannot close database (%s)", strerror(errno) );
		SOTP_ERROR_RET( SOTP_ERR_IO, strdup( errbuf ) );
	}
	return 0;
}


/* Get the current entry */
int sotp_db_get_entry( sotpdb_t *handle, sotpdb_entry_t *entry ) {
	char errbuf[100];

	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	} else if (!entry) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid entry" ) );
	}

	

	/* Fail if there are no entries in the database */
	if (handle->header.passwd_count==0) {
		/* Empty database */
		SOTP_ERROR_RET( SOTP_ERR_EMPTY_DB, NULL );
	}

	if (read( handle->fd, entry, sizeof(sotpdb_entry_t) )!=sizeof(sotpdb_entry_t)) {
		/* Cannot read entry ?? */
		sprintf( errbuf, "Error reading (%s)", strerror(errno) );
		SOTP_ERROR_RET( SOTP_ERR_IO, strdup( errbuf ) );
	}

	/* Convert the time stamp to host byte format */
	entry->stamp = ntohl( entry->stamp );
	
	/* sotp_db_get_entry doesn't advance the db pointer, so rewind back */
	if (lseek( handle->fd, -sizeof(sotpdb_entry_t), SEEK_CUR ) ==-1) {
		/* Cannot seek */
		sprintf( errbuf, "Error seeking (%s)", strerror(errno) );
		SOTP_ERROR_RET( SOTP_ERR_IO, strdup( errbuf ) );
	}
	return 0;
}


/* Add an entry */
int sotp_db_add_entry( sotpdb_t *handle, sotpdb_entry_t *entry ) {
	char errbuf[100];

	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	} else if (!entry) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid entry" ) );
	}


	/* Seek to the end of file */
	if (lseek( handle->fd, 0, SEEK_END )==-1) {
		/* Cannot seek */
		sprintf( errbuf, "Error seeking (%s)", strerror(errno) );
		SOTP_ERROR_RET( SOTP_ERR_IO, strdup( errbuf ) );
	}

	/* Convert the stamp to network byte order */
	entry->stamp = htonl(entry->stamp);
	
	/* Write the entry */
	if (write( handle->fd, entry, sizeof(sotpdb_entry_t) )!=sizeof(sotpdb_entry_t) ) {
		/* Cannot write */
		entry->stamp = ntohl(entry->stamp);
		sprintf( errbuf, "Error writing (%s)", strerror(errno) );
		SOTP_ERROR_RET( SOTP_ERR_IO, strdup( errbuf ) );
	}

	/* Convert the stamp to host byte order */
	entry->stamp = ntohl(entry->stamp);
	
	
	/* Update the header */

	/* If the database was empty we set the current pointer to this entry */
	if ( handle->header.passwd_count == 0 ) {
		handle->header.passwd_pointer =  0;
	}
	/* Update the number of passwords */
	handle->header.passwd_count = handle->header.passwd_count +1;

	/* Seek back to the original entry */
	return sotp_db_seek_entry( handle, handle->cur_entry );
}



/* Set an entry */
int sotp_db_write_entry( sotpdb_t *handle, sotpdb_entry_t *entry ) {
	char errbuf[100];
	
	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	} else if (!entry) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid entry" ) );
	}

	
	/* Fail if there are no entries in the database */
	if (handle->header.passwd_count==0) {
		/* Empty database */
		SOTP_ERROR_RET( SOTP_ERR_EMPTY_DB, NULL );
	}
	
	/* Convert the stamp to network byte order */
	entry->stamp = htonl(entry->stamp);
	
	
	/* Write the entry */
	if (write( handle->fd, entry, sizeof(sotpdb_entry_t) )!=sizeof(sotpdb_entry_t) ) {
		/* Cannot write */
		entry->stamp = ntohl(entry->stamp);
		sprintf( errbuf, "Error writing (%s)", strerror(errno) );
		SOTP_ERROR_RET( SOTP_ERR_IO, strdup( errbuf ) );
	}

	/* Convert the stamp to host byte order */
	entry->stamp = ntohl(entry->stamp);
	

	/* Success */
	return 0;
}
	

/* Advance one entry */
int sotp_db_next_entry( sotpdb_t *handle ) {
	char errbuf[100];

	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	}


	/* Fail if there are no entries in the database */
	if (handle->header.passwd_count==0) {
		/* Empty database */
		SOTP_ERROR_RET( SOTP_ERR_EMPTY_DB, NULL );
	}
	
	/* Check if we are already at the end of the DB */
	if (handle->cur_entry ==  handle->header.passwd_count  -1 ) {
		/* Already at the end */
		SOTP_ERROR_RET( SOTP_ERR_SEEK, strdup( "Trying to seek past last entry" ) );	
	}

	/* Seek to the next entry */
	if (lseek( handle->fd, sizeof(sotpdb_entry_t), SEEK_CUR ) == -1) {
		/* Cannot seek */
		sprintf( errbuf, "Error seeking (%s)", strerror(errno) );
		SOTP_ERROR_RET( SOTP_ERR_IO, strdup( errbuf ) );
	}
	
	/* Update the handle */
	handle->cur_entry++;
	
	/* Success */
	return 0;
}

/* Back one entry */
int sotp_db_prev_entry( sotpdb_t *handle ) {
	char errbuf[100];

	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	}

	/* Fail if there are no entries in the database */
	if (handle->header.passwd_count==0) {
		/* Empty database */
		SOTP_ERROR_RET( SOTP_ERR_EMPTY_DB, NULL );
	}
	
	
	/* Check if we are already at entry 0 */
	if (handle->cur_entry ==0) {
		/* Already at entry 0 */
		SOTP_ERROR_RET( SOTP_ERR_SEEK, strdup( "Trying to seek before first entry" ) );	
	}

	/* Seek to the previous entry */
	if (lseek( handle->fd, -sizeof(sotpdb_entry_t), SEEK_CUR ) == -1) {
		/* Cannot seek */
		sprintf( errbuf, "Error seeking (%s)", strerror(errno) );
		SOTP_ERROR_RET( SOTP_ERR_IO, strdup( errbuf ) );
	}

	/* Update the handle */
	handle->cur_entry--;

	/* Success */
	return 0;
}


/* Seek to an specified entry */
int sotp_db_seek_entry( sotpdb_t *handle, unsigned int idx ) {
	int tmp;
	char errbuf[100];

	/* Some sanity checks */
	if (idx >= handle->header.passwd_count) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid index" ) );
	}else if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	}

	/* Seek */
	tmp = sizeof(sotpdb_header_t) + sizeof(sotpdb_entry_t)*idx;
	if (lseek( handle->fd, tmp, SEEK_SET )==-1) {
		/* Cannot seek */
		sprintf( errbuf, "Error seeking (%s)", strerror(errno) );
		SOTP_ERROR_RET( SOTP_ERR_IO, strdup( errbuf ) );
	
	}

	/* Success */
	handle->cur_entry = idx;
	return 0;
}	



/* Get current entry index */
int sotp_db_get_entry_idx( sotpdb_t *handle, int *idx ) {
	
	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	} else if (!idx) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid index pointer" ) );
	}

	if (handle->header.passwd_count==0) {
		/* Empty database */
		SOTP_ERROR_RET( SOTP_ERR_EMPTY_DB, NULL );
	}
	
	*idx = handle->cur_entry;

	return 0;
}


/* Write the header to the file */
int sotp_db_write_header( sotpdb_t *handle ) {
	off_t cur_pos;
	char errbuf[100];

	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	}

	/* Save our current position */
	cur_pos = lseek( handle->fd, 0, SEEK_CUR );

	/* Seek to the begin */
	if (lseek( handle->fd, 0, SEEK_SET) == -1) {
		/* Cannot seek */
		sprintf( errbuf, "Error seeking (%s)", strerror(errno) );
		SOTP_ERROR_RET( SOTP_ERR_IO, strdup( errbuf ) );
	}

	/* Convert header to network byte order */
	header2nbo( &handle->header );
	
	/* Write the header */
	if (write( handle->fd, &handle->header, sizeof(sotpdb_header_t) ) != sizeof(sotpdb_header_t)) {
		sprintf( errbuf, "Error writing (%s)", strerror(errno) );
		SOTP_ERROR_RET( SOTP_ERR_IO, strdup( errbuf ) );
	}
	
	/* Seek back to the original position */
	if (lseek( handle->fd, cur_pos, SEEK_CUR ) == -1) {
		/* Cannot seek */
		sprintf( errbuf, "Error seeking (%s)", strerror(errno) );
		SOTP_ERROR_RET( SOTP_ERR_IO, strdup( errbuf ) );
	}
	
	/* Reconvert to host byte order */
	header2hbo( &handle->header );

	/* Sucess */
	return 0;
}
	

/* Get & set the configuration */
int sotp_db_get_config( sotpdb_t *handle, sotpdb_cfg_t *cfg ) {

	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	} else if (!cfg) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid configuration pointer" ) );
	}

	/* Copy */
	memcpy( cfg,  &handle->header.conf, sizeof(sotpdb_cfg_t) );

	return 0;
}


int sotp_db_set_config( sotpdb_t *handle, const sotpdb_cfg_t *cfg ){
	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	} else if (!cfg) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid configuration pointer" ) );
	}

	/* Copy */
	memcpy( &handle->header.conf, cfg, sizeof(sotpdb_cfg_t) );
	return 0;
}




/* Advance the password pointer */
int sotp_db_auth_ok( sotpdb_t *handle ) {
	

	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	}


	/* Only advance the password pointer if there is another entry after this one ;-) */
	if (handle->header.passwd_pointer < handle->header.passwd_count -1 ) {
		handle->header.passwd_pointer++;
	} else{
		/* No more new passwords */
		handle->header.conf.flags = handle->header.conf.flags | SOTPDB_FL_EXHAUSTED;
	}

	handle->header.auth_errors = 0;

	/* Write back the header */
	sotp_db_write_header( handle );

	return 0;
}


/* Increment the number of auth errors */
int sotp_db_auth_failed( sotpdb_t *handle ){


	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	}

	handle->header.auth_errors ++;
	return 0;
}



/* Get the number of auth errors with the current password pointer */
int sotp_db_get_auth_errors( sotpdb_t *handle, int *nerrors ) {


	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	} else if (!nerrors) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid nerrors pointer" ) );
	}

	*nerrors = handle->header.auth_errors;
	return 0;
}


/* Get the creation time of the database */
int sotp_db_get_creation_time( sotpdb_t *handle, time_t *when ){
	
	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	} else if (!when) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid time pointer" ) );
	}

	*when = (time_t) handle->header.gen_time;
	return 0;
}

/* Gets the number of passwords in a database */
int sotp_db_get_password_count( sotpdb_t *handle, int *npasswords ) {
	
	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	} else if (!npasswords) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid result pointer" ) );
	}


	*npasswords = handle->header.passwd_count;
	return 0;
}

/* Gets the password pointer of the database */
int sotp_db_get_password_pointer( sotpdb_t *handle, int *pointer ) {
	/* Check arguments */
	if (!handle) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid handle" ) );
	} else if (!pointer) {
		SOTP_ERROR_RET( SOTP_ERR_ARGS, strdup( "Invalid result pointer" ) );
	}


	*pointer = handle->header.passwd_count;

	return 0;
}
