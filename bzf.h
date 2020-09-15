#include <stdio.h>

extern char* bz_curfile;
extern unsigned long bz_curfile_size;

typedef unsigned char   Bool;

Bool bz_uncompressStream ( FILE *zStream, FILE *stream );
void bz_compressStream ( FILE *stream, FILE *zStream );

