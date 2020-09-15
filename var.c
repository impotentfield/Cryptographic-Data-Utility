#include <stdlib.h>
#include <sys/types.h>
#include "basictypes.h"
#include "var.h"
//#define size_t unsigned long long
int filecount=0;
char* inputfile=0;
int listcounter=0;
WORD32 curblocksize=0;
WORD32 curkeysize=0;
size_t curfilesize=0;
unsigned long long originalfilesize=0;
unsigned char* initcbcblock=NULL;
WORD32 initcbcblocksize=0;
off_t rwoffset=0;
char enlpercent=0;
char decompress=0;
int listcount=0;
char** archivelist = NULL;
int archivecounter = 0;
int archivelist_size = 0;
int archivelist_count = 0;
int** rmrpathlist = NULL;
int rmrpathlistsz = 0;
int rmrpathcount = 0;
int rmrpathsnoe = 0;
unsigned long largest_entry_size = 0;
