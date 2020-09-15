#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <string.h>

#include "sys_linux.h"
#include "basictypes.h"

void printk(char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

#define INIT_PRAGMA \
	do { \
		init_system_static(); \
	} while ( 0 ) ;


static int device_descriptors[DEVICE_NUMBER];
static volatile int system_is_init = 0;

#define state_oflow 64
static const size_t state_size = 200 + state_oflow;
static u8* state_memory = NULL;

static int
open_fd( const char *name, const int times )
{
	int fd;
	struct stat lstat;
	int t=0;

	try_:

	fd = open( name, O_RDONLY );

	if( fd == -1 ) {
		if ( (t++ < times) && (times > 0) ) {
			goto try_;
		} else {
			printk("system call 'open()' failure on %s: %s", name, strerror(errno) );
			goto error_;
		}
	}

	if( fstat( fd, &lstat ) ) {
		printk("system call 'stat()' failure on %s: %s", name, strerror(errno) );
		goto error_;
	}

	goto ok_;
	error_:
		fd = -1;
	ok_:
	return fd;
}

static int
close_fd(const int fd)
{
	int n, i;

	try_:

	n = close(fd);

	if ( n == -1 ) {
		n = errno;

		if ( n == EIO || n == EINTR ) {
			i++;
			if(i<3)
			goto try_;
		}

	printk("system call 'close()' failure on fd %d: %s", fd, strerror(errno) );
	}

	return n; /* zero on success */
}

static size_t
write_fd( int fd, const void *buf, size_t bytes )
{
	size_t n, rbytes = bytes;

	while( rbytes > 0 ) {

	n  = (size_t) write( fd, buf, rbytes);

		if( n < 0 ) {
			if( errno == EINTR )
				continue;
			return -1;
		}

		rbytes -= n;
		buf = (u8*) (buf + n);
	}

	return bytes ;
}

static size_t
read_fd( int fd, const void *buf, size_t bytes )
{
	size_t n=0;
	size_t nread=0;

	do {
		do {
			n = (size_t) read(fd, (u8*)(buf + nread), bytes );
		} while( n == -1 && errno == EINTR );

		if( n == -1 )
			return -1;
		nread += n;

	} while( nread < bytes );

	return bytes;
}

static int
close_device(devices_linux devt)
{
	int fd, n;

	if ( (fd = device_descriptors[devt]) == -1 )
		return 0;

	n = close_fd(fd);
		if ( n != -1 )
			device_descriptors[devt] = -1;

	return n;
}

static int
init_system_static()
{
	int i;

	if ( !system_is_init ) {

//		secmem_init( 32768 );

		for( i = 0; i < DEVICE_NUMBER; i++)
			device_descriptors[i] = -1;

		state_memory = (u8*) smalloc(state_size);

		if ( !state_memory ) {
			system_is_init = -1;
			goto error_;
		}

		system_is_init=1;
	}

	error_:

	return system_is_init;
}

static int
close_system_static()
{
	int i;
	char *name;

	if ( system_is_init == 1 ) {

		for ( i = 0; i < DEVICE_NUMBER; i++ ) {
			if ( close_device( (devices_linux) i ) == -1 ) {
				resolve_device_name(i, name);
				printk("could not close entropy device %s", name);
			}
		}

		if ( state_memory ) {
			memset(state_memory, 0xff, state_size);
			memset(state_memory, 0xaa, state_size);
			memset(state_memory, 0x55, state_size);
			sfree(state_memory);
			state_memory = NULL;
		}

//	secmem_term();
	system_is_init = 0;

	} else if (system_is_init != 0) { /* SECURITY DEBUG: security debugging */
		printk("DEBUG tried to call while system not initialized correctly");
		return -1;
	}

	return system_is_init;
}

/*-------------------------------------*/
#include "options.h"
int init_system_linux()
{
	int reval;

	if ( (reval = init_system_static()) != -1 )
		reval = system_is_init;
//	printk("system initialization %d", reval);

	return reval;
}

int close_system_linux()
{
	int reval;
//	printk("system close %d", system_is_init);

	if ( (reval = close_system_static()) != -1 )
		reval = system_is_init;
	return reval;
}

size_t add_entropy(const void* ubuffer, size_t bytes)
{

	char *name = NULL;
	int fd=0;
	size_t n=0;
	mode_t mode = O_WRONLY;

	if ( !ubuffer || (bytes<=0) )
		return 0;

	INIT_PRAGMA

	n=0;

	resolve_device_name(enum_random, name);

		try_:
			fd = open( name, mode );

			if ( fd == -1 ) {

				if ( n < 3 ) { /* prudency or redundancy ? that is the question ... :'] */
					n++;
					goto try_;
				}
				printk("failed to open device %s for writing entropy: %s", name, strerror(errno));
				return -1;
			}

	printk("writing %u bytes to system entropy pool (%s) ...", (unsigned int) bytes, name);


	if ( (n = (size_t) write_fd( fd, ubuffer, bytes )) == -1 ) {
		printk("failed to write entropy to system wide pool: %s", ( strerror(errno) ));
	}
	else {
		printk("OK");
	}

	return n;

}

size_t sample_from_device( void* ubuffer, size_t bytes, devices_linux devt )
{
	struct timeval tv;
	struct stat lstat;
	fd_set setfd;
	size_t nn=0, nnn=0;
	int fd=0, n=0, sys_pragma=0;
	size_t ubytes = bytes, rbytes = 0, ptr_inc = 0;
	u8 *state_buffer = NULL;
	u8 *pbuffer = NULL;
	char *name = NULL;

	INIT_PRAGMA

	state_buffer = state_memory;
	pbuffer = (u8*) ubuffer;

	rbytes = bytes;

	resolve_device_name(devt, name);
	if ( (fd = device_descriptors[(int)devt]) == -1 ){
		fd = open_fd( name, 5 );
			if ( fd == -1 ) return -1;
		device_descriptors[(int)devt] = fd;
    }

//	printk("retrieving %d byte samples from device %d, %s", (int) ubytes, (int) devt, name);

	ptr_inc = 0;

    while( ubytes ) {

	switch ( devt ) {

		case enum_urandom: /* non-blocking */
			if( fstat( fd, &lstat ) == -1 ){
				printk("system call 'stat()' failure on %s: %s", name, strerror(errno));
				if ( sys_pragma == 3 ){
					printk(" -- bailing...");
						return -1;
				}
				else{
					++sys_pragma;
					continue;
				}

			}
		break;

		case enum_random: /* blocking */
		default:
			FD_ZERO(&setfd);
			FD_SET(fd, &setfd);
			tv.tv_sec = 3;
			tv.tv_usec = 0;

			if( !(n=select(fd+1, &setfd, NULL, NULL, &tv)) ) {
				printk("linux device buffer %s is flushed, need %d bytes...", name, ubytes);
				continue;
			}
			else if( n == -1 ) {
				printk("system call 'select()' failure: %s", strerror(errno));
				if ( sys_pragma == 3 ){
					printk(" -- bailing...");
					return -1;
				}
				else{
					++sys_pragma;
					continue;
				}
			}

		break;

		break;

	}

		nn = read_fd(fd, state_buffer, (state_size-state_oflow)); /* read in 'state_size' chunks */

			if( nn > (state_size-state_oflow)) {
				printk("warning: overread of %d bytes from random device", nn);
				nn = 0;
			}

			if( nn == -1 ){
				printk("system call 'read()' error on random device: %s", strerror(errno));
				return -1;
			}

		if ( nn ) {
			if ( nn < (rbytes - ptr_inc) )
				nnn = nn;
			else
				nnn = (rbytes - ptr_inc);
			memcpy( (pbuffer + ptr_inc), state_buffer, nnn);
			ptr_inc += nnn;

			ubytes -= nnn;
		}
    }


    return rbytes;
}

#undef INIT_PRAGMA
