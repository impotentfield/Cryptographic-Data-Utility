/* minigzip.c -- simulate gzip using the zlib compression library
 * Copyright (C) 1995-2005 Jean-loup Gailly.
 * For conditions of distribution and use, see copyright notice in zlib.h
 */

/*
 * minigzip is a minimal implementation of the gzip utility. This is
 * only an example of using zlib and isn't meant to replace the
 * full-featured gzip. No attempt is made to deal with file systems
 * limiting names to 14 or 8+3 characters, etc... Error checking is
 * very limited. So use minigzip only for testing; use gzip for the
 * real thing. On MSDOS, use only on file names without extension
 * or in pipe mode.
 */

/* @(#) $Id$ */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "zlib/zlib.h"
#define smalloc malloc
#define sfree free
#define srealloc realloc
//#define USE_MMAP

#ifdef STDC
#  include <string.h>
#  include <stdlib.h>
#endif

#ifdef USE_MMAP
#  include <sys/types.h>
#  include <sys/mman.h>
#  include <sys/stat.h>
#endif

#define BUFLEN      4096
#define MAX_NAME_LEN 1024

#ifdef MAXSEG_64K
#  define local static
   /* Needed for systems with limitation on stack size. */
#else
#  define local
#endif

void error            OF((const char *msg));
int gz_compress      OF((FILE   *in, gzFile out));
#ifdef USE_MMAP
int  gz_compress_mmap OF((FILE   *in, gzFile out));
#endif
int gz_uncompress    OF((gzFile in, FILE   *out));
int file_compress    OF((char  *file, char *outfile, char *mode));
int file_uncompress  OF((char  *file));

/* ===========================================================================
 * Display error message and exit
 */
void zlerror(msg)
    const char *msg;
{
    fprintf(stderr, "\nminigzip.c: %s", msg);
}
/* ===========================================================================
 * Compress input to output then close both files.
 */

int gz_compress(in, out)
    FILE   *in;
    gzFile out;
{
    unsigned char *buf;
	unsigned char *outbuf;
    int len;
    int err;

#ifdef USE_MMAP
    /* Try first compressing with mmap. If mmap fails (minigzip used in a
     * pipe), use the normal fread loop.
     */
    if (gz_compress_mmap(in, out) == Z_OK) return;
#endif
	/* enciu - use secure memory for original data  */
	buf = (unsigned char *) smalloc(BUFLEN);
	outbuf = (unsigned char *) smalloc(BUFLEN);
		if ( !buf || !outbuf ) {
			zlerror("could not allocate 4096 bytes");
			return -1;
		}
    for (;;) {
        len = (int)fread(buf, 1, sizeof(buf), in);
        if (ferror(in)) {
            perror("fread");
            return -1;
        }
        if (len == 0) break;

        if (gzwrite(out, buf, (unsigned)len) != len){
		zlerror(gzerror(out, &err));
		return -1;
		}
    }
    fclose(in);
    if (gzclose(out) != Z_OK){ zlerror("failed gzclose"); }
	sfree(buf);
	sfree(outbuf);

return 0;
}

#ifdef USE_MMAP /* MMAP version, Miguel Albrecht <malbrech@eso.org> */

/* Try compressing the input file at once using mmap. Return Z_OK if
 * if success, Z_ERRNO otherwise.
 */
int gz_compress_mmap(in, out)
    FILE   *in;
    gzFile out;
{
    int len;
    int err;
    int ifd = fileno(in);
    caddr_t buf;    /* mmap'ed buffer for the entire input file */
    off_t buf_len;  /* length of the input file */
    struct stat sb;
	unsigned char *mapbuf;

    /* Determine the size of the file, needed for mmap: */
    if (fstat(ifd, &sb) < 0) return Z_ERRNO;
    buf_len = sb.st_size;
    if (buf_len <= 0) return Z_ERRNO;

	/* @(#) enciu -- use secure memory */
	mapbuf = (unsigned char*) smalloc(buf_len);
	
    /* Now do the actual mmap: */
//    buf = mmap((caddr_t) 0, buf_len, PROT_READ, MAP_SHARED, ifd, (off_t)0);
    buf = mmap(mapbuf, buf_len, PROT_READ, MAP_SHARED, ifd, (off_t)0);
    if (buf == (caddr_t)(-1)) return Z_ERRNO;

    /* Compress the whole file at once: */
    len = gzwrite(out, (char *)buf, (unsigned)buf_len);

    if (len != (int)buf_len) zlerror(gzerror(out, &err));

    munmap(buf, buf_len);
	sfree(mapbuf);
    fclose(in);
    if (gzclose(out) != Z_OK) zlerror("failed gzclose");
    return Z_OK;
}
#endif /* USE_MMAP */

/* ===========================================================================
 * Uncompress input to output then close both files.
 */
int gz_uncompress(in, out)
    gzFile in;
    FILE   *out;
{
    unsigned char buf[BUFLEN];
	unsigned char outbuf[BUFLEN];
    int len;
    int err;

    for (;;) {
        len = gzread(in, buf, sizeof(buf));
        if (len < 0) zlerror (gzerror(in, &err));
        if (len == 0) break;

        if ((int)fwrite(buf, 1, (unsigned)len, out) != len) {
            zlerror("failed fwrite");
			return -1;
        }
    }
    if (fclose(out)) zlerror("failed fclose");

    if (gzclose(in) != Z_OK) zlerror("failed gzclose");

return 0;
}

int file_compress(char *file, char *outfile, char *mode)
{
    int i;
    FILE  *in;
    gzFile out;

    in = fopen(file, "rm");
    if (in == NULL) {
        perror(file);
        return -1;
    }
	setvbuf(in, NULL, _IONBF, 0);

	out = gzopen(outfile, mode);
    if (out == NULL) {
        fprintf(stderr, "\ncan't gzopen %s: %s", outfile, strerror(errno));
        return -1;
    }

	if ( gz_compress(in, out) == -1 )
		return -1;

	return 0;
}

int file_uncompress(file)
    char  *file;
{
    FILE  *out;
    gzFile in;
    int fd, i;
	char *tempfilename;

    tempfilename = (char*) malloc(strlen(file)+13+2);
	strcpy(tempfilename, file);
	strcat(tempfilename, ".decompressed");

	in = gzopen(file, "rb");
    if (in == NULL) {
        fprintf(stderr, "\ncan't gzopen %s", file);
        return -1;
    }

	out = fopen(tempfilename, "wb");
    if (out == NULL) {
        perror(file);
        return -1;
    }
	setvbuf(out, NULL, _IONBF, 0);
_retry:
    if ( gz_uncompress(in, out) == -1 ) {
		merror("compression error, retrying\n");
		fclose(out);
		return -1;
	}

	{ struct stat sb; stat(tempfilename, &sb); if ( sb.st_size == 0 ) { merror("truncation detected\n"); goto _retry; } }

	i = rename(tempfilename, file);
		if ( i == -1 ) {
			fprintf(stderr, "\n%s: could not rename file: %s", file, strerror(errno));
			remove(tempfilename);
			free(tempfilename);
			return -1;
		}

	free(tempfilename);

	return 0;
}
