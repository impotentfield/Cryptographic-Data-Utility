#include <sys/types.h>
#include <stdio.h>

#define DEVICE_NUMBER 2
#define RANDOM_DEVICE_NAME "/dev/random"
#define URANDOM_DEVICE_NAME "/dev/urandom"

typedef enum {
	enum_random  =0,
	enum_urandom =1
} devices_linux;

#define resolve_device_name(_xenum_, _p_) \
	do { \
		if ( _xenum_ == enum_random ) \
			_p_ = RANDOM_DEVICE_NAME; \
		else \
		if ( _xenum_ == enum_urandom ) \
			_p_ = URANDOM_DEVICE_NAME; \
		else \
			_p_ = URANDOM_DEVICE_NAME; \
	} while(0) ;

int init_system_linux();
int close_system_linux();
/* return how many added */
size_t add_entropy(const void* ubuffer, size_t bytes);
/* return how many read */
size_t sample_from_device( void* pbuffer, size_t bytes, devices_linux devt);

extern __inline__
int init_system() {
	return init_system_linux();
}
extern __inline__
size_t reseed_system(const void* ubuffer, size_t bytes) {
	return add_entropy(ubuffer, bytes);
}
extern __inline__
size_t gather_random_fast(void* pbuffer, size_t bytes) {
	return sample_from_device( pbuffer, bytes, (devices_linux) enum_urandom );
}
extern __inline__
size_t gather_random_slow(void* pbuffer, size_t bytes) {
	return sample_from_device( pbuffer, bytes, (devices_linux) enum_random );
}
extern __inline__
int close_system() {
	return close_system_linux();
}

extern __inline__
void printk(char *, ...);
#include <memory.h>
/* we used gpgs secmem.h/c code and all it does is put all process memory into the ram instead of the page allocation table so in cpdu.c we use mlockall() function call to attempt to lock all the program memory space into the ram to perform the same function as secmem attempts to do so we dont need really gpgs secmem code rather moreso locking the memory table into the ram with mlockall() being performed during program operation needs root priveleges */
#define smalloc malloc
#define sfree free
#define srealloc realloc
#if 0
extern __inline__
void *smalloc( size_t size ) {
        return secmem_malloc( size );
}

extern __inline__
void *srealloc( void *ptr, size_t newsize ) {
        return secmem_realloc( ptr, newsize );
}

extern __inline__
void sfree ( void *ptr ) {
        return secmem_free( ptr );
}
#endif
