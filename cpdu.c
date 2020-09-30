#include <unistd.h>
#include <dirent.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/time.h>

#include "cpdu.h"
#include "cipher.h"
#include "var.h"
#include "options.h"
#include "error.h"
#include "ciphervar.h"
#include "sha1.h"
#include "zlf.h"
#include "bzf.h"

#define sfree free
#define smalloc malloc
#define srealloc realloc

typedef enum
{	cpdu_archive=0,
	cpdu_encrypted=1,
	cpdu_backup_archive=2,
	cpdu_none =3
} cpdu_file_type;

/* -- start main -- */

/* -- cpdu.c variables -- */
unsigned char* passbuf=NULL;
unsigned long* passbufsz=NULL;
int margc;
char **margv;
char *archive_name = NULL;
static int file_processed_count = 0;
unsigned char check_hash[SHA1_DIGESTSIZE];
int normv_int = 0;
char *curfile, *curfileout;
size_t wpsz_int = 0, wpdn_int = 0, wpszdn_int = 0; 
char *topdir = NULL;
char *topentry = NULL;
char masterkeydbfilename[200];
char *archive_ext_set_file = "set_archive_ext\0";
char *cur_ext = ".cpdu.package\0";
unsigned long long session_total_size = 0;
unsigned long long session_current_size = 0;
char** entrylist = NULL;
int entrycounter = 0;
int entrylist_size = 0;
int entrylist_count = 0;
int got_backup_archive = 0;

typedef struct {
	char *name;
	unsigned long count;
	unsigned long dircount;
} archive_entry;

archive_entry **archive_entry_status_list;
unsigned long archive_entry_status_list_count = 0;
unsigned long archive_entry_status_list_size = 0;
unsigned long asel_counter = 0;

/* -- cpdu.c variables -- */

/* -- cpdu.c constants -- */
const char cpdu_archive_hdr[] = "cpdu_encrypted_archive";
const char cpdu_encrypt_hdr[] = "cpdu_encrypted_file";
const char cpdu_archive_backup_hdr[] = "cpdu_backup_archive";

/* -- cpdu.c constants -- */

/* -- function prototypes -- */
void chmod_secure_file(char *file);
void chmod_unsecure_file(char *file);
void chmod_secure_mykeydir();
void chmod_unsecure_mykeydir();
char *make_mykeydir();
char *make_mydir();
char **getdir(char *dirname, int recurse);
size_t init_file_encrypt(void* pctx, FILE* in, FILE* out);
size_t init_file_decrypt(void* pctx, FILE* in, FILE* out);
int getpassword(int ciphermode, char *prompt);
int read_stdin_to_fd(int fd_out);
int write_fd_to_stdout(int fd_in);
void _secureclearpassbuf();
void secure_local_key_set();
void secure_local_key_get();
char *get_current_dir_name(){return getenv("PWD");}
int cpdu_archive_unload(char* larchive_name);
int cpdu_archive_load(char* larchive_name);
unsigned char* sha1_get_file_hash(char* file);
char *make_myrecoverdir();
char *rm_relative_path(char* name);
int copy_file(char *file, char* new);
char *mk_recoverdb_entry(char *entry);
int addkey_to_masterkeylist();
int getkey_from_masterkeylist(char *digest);
void status_print_session_done();
void cpdu_signal_sigint(int signal);
cpdu_file_type cpdu_query_file_type(char *file);
int generate_keyfile(char *keyfile, size_t fsize);
unsigned char *crunch_key(unsigned char *xkey, unsigned long xkeysize, unsigned char *keybuf, unsigned long outsize);
int read_key_from_keyfile(char *keyfile, unsigned char *keybuf, unsigned long keysize);
size_t encrypt_header(void *ctx, FILE* fs);
int decrypt_header(FILE* fs);
void secure_commit_key();
char *clf_strip_path_dlmtr(char* name);
char* get_archive_ext() { return cur_ext; } /* FIXME: @ */
void status_print_file_done();
void print_archive_list(char* larchive_name);
char** menu_getdir(char* dirname);

void archive_access_error(char* file)
{
	int r;
	r = access(file, R_OK|W_OK);

	if ( r == -1 ) {
		merror("insufficient permissions on file %s: %s\n", file, strerror(errno));
		merror("session/archive error, incomplete session due to permissions error on file '%s'\n", file);
		exit(0);
	}
}

int diff(int a, int b)
{
	if ( a > b ) return a - b;
	if ( b > a ) return b - a;	
	
}


#include <ncurses.h>
#include <menu.h>

char** il;
int ilcnt;
int ilsz;
char** choices;

void menu_directory_select()
{
	ITEM **my_items;
	int c;				
	MENU *my_menu;
	int n_choices, i;
	ITEM *cur_item;
	int current = 0;
	char *currentdir;
	char* prev_dir;
	char* fdir = getenv("PWD");
	unsigned long menu_count = 0;

	currentdir = fdir;
	prev_dir = currentdir;

	entrylist = NULL;

	il = (char**) malloc(ilsz+=sizeof(char**));
	ilcnt = 0;

	initscr();
	cbreak();
	noecho();
	keypad(stdscr, TRUE);

	__dir:
	erase();
	if ( entrylist ) free(entrylist);
	current = 0;
	entrylist = menu_getdir(currentdir);
	if ( !entrylist ) { currentdir = prev_dir; goto __dir; }
	mvprintw(LINES - 5, 0, "'E' to Exit. Press 'Enter' for each file to decrypt, Press 'A' to select all in directory.: %s", currentdir);

	n_choices = (int) entrylist_count;
	choices = entrylist;
	my_items = (ITEM **)calloc(n_choices + 1, sizeof(ITEM *));

	for(i = 0; i < n_choices; ++i)
	        my_items[i] = new_item(choices[i], NULL);
	my_items[n_choices] = (ITEM *)NULL;
	my_menu = new_menu((ITEM **)my_items);

	{ int x, y;
        getmaxyx(stdscr, y, x);
        set_menu_format(my_menu, y-10, 1);
	}

	post_menu(my_menu);
	refresh();

	while((c = getch()) != 'E')
	{   
		switch(c)
	    {
			case KEY_DOWN:
		        menu_driver(my_menu, REQ_DOWN_ITEM);
				break;
			case KEY_UP:
				menu_driver(my_menu, REQ_UP_ITEM);
				break;
			case '\n':
			{ struct stat sb; char *string;   		
					string = (char*) malloc(strlen(fdir)+strlen(item_name(current_item(my_menu)))+3);
	    				strcpy(string, fdir);
					strcat(string, "/");
					strcat(string, "\0");
	    				strcpy(string+strlen(fdir)+1, item_name(current_item(my_menu)));
	    				strcat(string, "\0");
					stat(string, &sb);					
					if ( S_ISDIR(sb.st_mode) ) {
					prev_dir = currentdir;
					fdir = currentdir = string; 
					goto __dir;
					}
			}
					{ char* string;
	        			string = (char*) malloc(strlen(fdir)+strlen(item_name(current_item(my_menu)))+3);
		    			strcpy(string, fdir);
					strcat(string, "/");
					strcat(string, "\0");
					strcpy(string+strlen(fdir)+1, item_name(current_item(my_menu)));
	    				strcat(string, "\0");
					mvprintw(LINES - 2, 0, "%s                                                  ", string);
					il = (char**) realloc(il, ilsz+=sizeof(char*));
					il[ilcnt++] = strdup(string);
					}
			menu_count++;
			mvprintw(LINES - 3, 0, "Items Selected for Processing: %d", menu_count);
			break;
			case 'A':
			{ int a; struct stat sb;
			  for(a=0; a<entrylist_count; a++) {
					{ char* string;        		
					string = (char*) malloc(strlen(fdir)+strlen(entrylist[a])+3);
		    			strcpy(string, fdir);
					strcat(string, "/");
					strcat(string, "\0");
		    			strcpy(string+strlen(fdir)+1, entrylist[a]);
		    			strcat(string, "\0");
	
					{ struct stat sb;
					stat(string, &sb);
					if ( S_ISDIR(sb.st_mode) ) {
					free(string); continue;
					}
					}

					il = (char**) realloc(il, ilsz+=sizeof(char*));
					il[ilcnt++] = strdup(string);
					}
				menu_count++;
		 	  	}
			  }
			mvprintw(LINES - 3, 0, "Items Selected for Processing: %d", menu_count);
			break;
		}
	}	

	free_item(my_items[0]);
	free_item(my_items[1]);
	free_menu(my_menu);
	endwin();	
}

const char *processedlist_filename = "/.cpdu_processedlist";
int hottrackcount = 0;
int _reseal_fillentrylist()
{
 char* string;
 int sz;
 char *c;
 char* filename;
 FILE *f;
 struct stat sb;
 size_t sizefile = 0;
 int null_count = 0;
 
  filename = (char*) malloc(strlen(getenv("HOME"))+strlen(processedlist_filename)+1);
  strcpy(filename, getenv("HOME"));
  strcat(filename, processedlist_filename);
  
 f = fopen(filename, "r");
 { int r; r = stat(filename, &sb); if ( r == -1 ) { merror("no hot track list available. maybe all files were decrypted\n"); return 1; } }
  
 entrylist = NULL;
 entrylist_count = 0;
 entrylist_size = 0;
 string = NULL;
 sz = 0;
 
 do {
    int r;
    char c;
    r = fread(&c, 1, 1, f);
	if ( sb.st_size == ++sizefile) goto string__;
    if ( c == '\n' ) { 
	  string__:
      string = (char*) realloc(string, ++sz);
      string[sz-1] = '\0';
    if ( cpdu_query_file_type(string) == cpdu_encrypted ) { sz = 0; null_count = 1; continue; } else { hottrackcount = 1; }
    if ( entrylist == NULL ) { entrylist = (char**) malloc(entrylist_size+=sizeof(char**)); }
      entrylist = (char**) realloc(entrylist, entrylist_size+=sizeof(char*));
      entrylist_count += 1;
      entrylist[entrylist_count-1] = strdup(string);
 //fprintf(stderr, "entrylist: %s. string: %s\n", entrylist[entrylist_count-1], string);
      sz = 0;
    } else {
     if ( sz == 0 ) { string = (char*) malloc(1); sz++; }
     else { string = (char*) realloc(string, ++sz); }
     string[sz-1] = c;
    }
 } while( !(sb.st_size == sizefile) );
 menu__:
 //if ( null_count && entrylist_count ) { fclose(f); remove(filename); { int i; for ( i = 0; i<entrylist_count; i++)
   //  add_to_processedlist(entrylist[i]);
 //}
 if ( null_count && !entrylist_count ) { hottrackcount = 0; merror("all hot track files are encrypted already\n"); fclose(f); return 1; } else { fclose(f); }

 return 0;
}

int _purge_fillentrylist()
{
 char* string;
 int sz;
 char *c;
 char* filename;
 FILE *f;
 struct stat sb;
 size_t sizefile = 0;
 int null_count = 0;
 
  filename = (char*) malloc(strlen(getenv("HOME"))+strlen(processedlist_filename)+1);
  strcpy(filename, getenv("HOME"));
  strcat(filename, processedlist_filename);
  
 f = fopen(filename, "r");
 { int r; r = stat(filename, &sb); if ( r == -1 ) { merror("no hot track list currently. if there are encrypted files that you are not sure are encrypted in locations that cant be determined, run 'cpdu -dr [BASE_DIRECTORY]' and all files that are encrypted with cpdu will automatically be detected.\n"); remove(filename); hottrackcount = 1; return 1; } }
  
 entrylist = NULL;
 entrylist_count = 0;
 entrylist_size = 0;
 string = NULL;
 sz = 0;
 
 do {
    int r;
    char c;
    r = fread(&c, 1, 1, f);
	if ( sb.st_size == ++sizefile) goto string__;
    if ( c == '\n' ) { 
	  string__:
      string = (char*) realloc(string, ++sz);
      string[sz-1] = '\0';
    if ( cpdu_query_file_type(string) == cpdu_none ) { null_count++; }
    if ( entrylist == NULL ) { entrylist = (char**) malloc(entrylist_size+=sizeof(char**)); }
      entrylist = (char**) realloc(entrylist, entrylist_size+=sizeof(char*));
      entrylist_count += 1;
      entrylist[entrylist_count-1] = strdup(string);
 //fprintf(stderr, "entrylist: %s. string: %s\n", entrylist[entrylist_count-1], string);
      sz = 0;
    } else {
     if ( sz == 0 ) { string = (char*) malloc(1); sz++; }
     else { string = (char*) realloc(string, ++sz); }
     string[sz-1] = c;
    }
 } while( !(sb.st_size == sizefile) );
 menu__:
 //if ( null_count && entrylist_count ) { fclose(f); remove(filename); { int i; for ( i = 0; i<entrylist_count; i++)
   //  add_to_processedlist(entrylist[i]);
 //}
 //if ( null_count && !entrylist_count ) { hottrackcount = 0; merror("all hot track files are encrypted already\n"); fclose(f); return 1; } else { fclose(f); }
	if ( null_count == entrylist_count ) { hottrackcount = 1; }
 	remove(filename);
 fclose(f);
 return 0;
}

void menu_()
{	ITEM **my_items;
	int c;				
	MENU *my_menu;
	int n_choices, i;
	ITEM *cur_item;
	int current = 0;

	initscr();
	cbreak();
	noecho();
	keypad(stdscr, TRUE);
	
	il = (char**) malloc(sizeof(char**));
	ilsz+=sizeof(char*);
	ilcnt = 0;

	n_choices = (int) entrylist_count;
	choices = entrylist;
	my_items = (ITEM **)calloc(n_choices + 1, sizeof(ITEM *));

	for(i = 0; i < n_choices; ++i)
	        my_items[i] = new_item(choices[i], NULL);
	my_items[n_choices] = (ITEM *)NULL;

	my_menu = new_menu((ITEM **)my_items);
    { int x, y;
        getmaxyx(stdscr, y, x);
        set_menu_format(my_menu, y-10, 1);
    }
    
    if ( opts->print_processed_list ) {
	  mvprintw(LINES - 2, 0, "'E' to Exit. Press 'Enter' for each file to decrypt, Press 'A' to select all.");
	}
	else {
	  mvprintw(LINES - 2, 0, "'E' to Exit. Press 'Enter' for each file to Encrypt");
	}
	
	post_menu(my_menu);
	refresh();

	while((c = getch()) != 'E')
	{
	switch(c)
	{
		case KEY_DOWN:
			menu_driver(my_menu, REQ_DOWN_ITEM);
		break;
		case KEY_UP:
			menu_driver(my_menu, REQ_UP_ITEM);
                break;
		case '\n':
			il = (char**) realloc(il, ilsz+=sizeof(char*));
			il[ilcnt++] = strdup(item_name(current_item(my_menu)));
		break;
		case 'A':
		{ int a;
		for(a=0; a<entrylist_count; a++)
		{
			il = (char**) realloc(il, ilsz+=sizeof(char*));
			il[ilcnt++] = strdup(entrylist[a]);
		}
		}
		break;
	}
	}	

	free_item(my_items[0]);
	free_item(my_items[1]);
	free_menu(my_menu);
	endwin();
}


void add_to_processedlist(char* string_filename)
{
  static FILE* f;
  static char* filename;
  static is_open = 0;
  if ( is_open == 0 ) {
  filename = (char*) malloc(strlen(getenv("HOME"))+strlen(processedlist_filename)+1);
  strcpy(filename, getenv("HOME"));
  strcat(filename, processedlist_filename);
  f = fopen(filename, "a+");
  is_open = 1;
  }
  fprintf(f, "%s\n", string_filename);
}

#include <sys/time.h>
#include <time.h>
void write_recovery_log(int argc, char** argv)
{
        time_t log_time;
        FILE* log;
        char* filename;
        filename = (char*) malloc(strlen(getenv("HOME"))+strlen("/.cpdu/cpdu_sessions_log")+1);
        sprintf(filename, "%s%s\0", getenv("HOME"), "/.cpdu/cpdu_sessions_log");
        log = fopen(filename, "a+");
        time(&log_time);
        fprintf(log, "\n-------------------------\n");
		fprintf(log, "%sCryptographic Data Utility Session", ctime(&log_time));
		fprintf(log, "\nWorking directory: %s", get_current_dir_name());
		fprintf(log, "\n-------------------------\n");
        fprintf(log, "Number of files: %d\n", entrylist_count);
		fprintf(log, "Command Line: ");
        {
			int i;
			for(i=0;i<argc;i++) {
				fprintf(log, "%s ", argv[i]);
			}
		}
  		fprintf(log, "\n-------------------------\n");
        /* 9 line breaks before entrylist */
		{
			int i;
			for(i=0;i<entrylist_count;i++) {
				fprintf(log, "%s\n", entrylist[i]);
			}
		}
}

int print_processed_list()
{
 char* string;
 int sz;
 char *c;
 char* filename;
 FILE *f;
 struct stat sb;
 size_t sizefile = 0;
 int null_count = 0;
 
  filename = (char*) malloc(strlen(getenv("HOME"))+strlen(processedlist_filename)+1);
  strcpy(filename, getenv("HOME"));
  strcat(filename, processedlist_filename);
  
 f = fopen(filename, "r");
 { int r; r = stat(filename, &sb); if ( r == -1 ) { merror("no hot track list available. maybe all files were decrypted\n"); return 1; } }
  
 entrylist = NULL;
 entrylist_count = 0;
 entrylist_size = 0;
 string = NULL;
 sz = 0;
 
 do {
    int r;
    char c;
    r = fread(&c, 1, 1, f);
	if ( sb.st_size == ++sizefile) goto string__;
    if ( c == '\n' ) { 
	  string__:
      string = (char*) realloc(string, ++sz);
      string[sz-1] = '\0';
    if ( cpdu_query_file_type(string) == cpdu_none ) { sz = 0; null_count = 1; continue; }
    if ( entrylist == NULL ) { entrylist = (char**) malloc(entrylist_size+=sizeof(char**)); }
      entrylist = (char**) realloc(entrylist, entrylist_size+=sizeof(char*));
      entrylist_count += 1;
      entrylist[entrylist_count-1] = strdup(string);
 //fprintf(stderr, "entrylist: %s. string: %s\n", entrylist[entrylist_count-1], string);
      sz = 0;
    } else {
     if ( sz == 0 ) { string = (char*) malloc(1); sz++; }
     else { string = (char*) realloc(string, ++sz); }
     string[sz-1] = c;
    }
 } while( !(sb.st_size == sizefile) );
 menu__:
 //if ( null_count && entrylist_count ) { fclose(f); remove(filename); { int i; for ( i = 0; i<entrylist_count; i++)
   //  add_to_processedlist(entrylist[i]);
 //}
 if ( null_count && !entrylist_count ) { merror("no files are encrypted\n"); fclose(f); return 1; } else { fclose(f); }
 menu_();
 return 0;
}

/* -- function prototypes -- */

/* -- main -- */
#include <sys/mman.h>
#include <signal.h>
int main(int argc, char **argv)
{
	struct stat statbuf;
	struct sigaction act_sigint;
	char dostdin=0;
	char *n;

	opts = parse_options(argc, argv);

    if ( opts->backup ) opts->ciphermode = CIPHER_MODE_ENCRYPT;

	if ( opts->doarchive  && !opts->autonamearchive ) {
		if ( !strchr(opts->archive, (int) '.') ) {
		n = (char*) malloc(strlen(opts->archive)+strlen(get_archive_ext())+1);
		strcpy(n, opts->archive);
		strcpy(n+strlen(opts->archive), get_archive_ext());
		strcat(n, "\0");
		opts->archive = n;
		}
	}

	if ( mlockall(MCL_CURRENT) == -1 ) {
        fprintf(stderr, "%s: error locking process virtual memory space: %s\n", argv[0], strerror(errno));
	}

	act_sigint.sa_handler = cpdu_signal_sigint;
	sigemptyset(&act_sigint.sa_mask);
	act_sigint.sa_flags = 0;
	sigaction(SIGINT, &act_sigint, 0);
	if ( opts->doarchive && opts->menu ) {
            merror("cannot create archives in directory tree selection mode\n");
            exit(1);
    	}
	
	if ( opts->menu ) {
		menu_directory_select();
	}

    if ( opts->listarchive ) {
         print_archive_list(opts->archive);
         exit(0);
    }

	if ( opts->print_processed_list ) { int r; r = print_processed_list(); if ( r == 1 ) exit(1); entrylist = il; entrylist_count = ilcnt; entrycounter = 0; ciphermode = CIPHER_MODE_DECRYPT; }    
	init_system();

	ciphermode = opts->ciphermode; /* global variable 'ciphermode' set for the session */
	//dostdin = opts->rstdin; /* once stdin is finished 'dostdin' variable is set to 0 */
    dostdin = 0;

    if ( opts->resealhottracklist ) {
        _reseal_fillentrylist();
		if ( hottrackcount == 0 ) { merror("aborting\n"); exit(1); }
        ciphermode = CIPHER_MODE_ENCRYPT;
    }

	if ( opts->purgehottracklist ) {
		_purge_fillentrylist();
		if ( hottrackcount == 1 ) { merror("no files to decrypt. hot track list was removed. the hot track session list is set to be filled again with track locations upon any further encryption sessions.\n"); exit(1); }
		ciphermode = CIPHER_MODE_DECRYPT;
	}

/* other option processing: we first handle to see if other options are set, if so we process them */
	if ( opts->slkeyset ) {
		secure_local_key_set();
		exit(0);
	}

	if ( opts->genkeyfile ) {
		generate_keyfile(opts->keyfile, opts->gensize);
		chmod_secure_file(opts->keyfile);
		exit(0);
	}

	if ( ciphermode == CIPHER_MODE_ENCRYPT )
	{   cipherctx = determineCipherContext(opts->cipher);
    		if ( !cipherctx ) {
                        merror("not able to determine cipher context.\n");
                        opts->destructor(opts);
                        close_system();
                        exit(0);
                }
	initcbcblock = (unsigned char*) malloc(curblocksize);
	initcbcblocksize = curblocksize;
    }

/* we recurse always in archive mode for reasons of safety */
if ( ciphermode==CIPHER_MODE_ENCRYPT && opts->doarchive ){
opts->recurse = 1;
}

archivelist = (char**) malloc(sizeof(char*));

if ( ciphermode==CIPHER_MODE_DECRYPT && opts->doarchive ){
	cpdu_file_type ft;
	if ( (ft = cpdu_query_file_type (opts->archive)) == cpdu_archive ) {
		archivelist = (char**) realloc(archivelist, archivelist_size +=sizeof(char*));
		archivelist[archivelist_count] = strdup(opts->archive);
		archivelist_count++;
	} else { merror("not a cpdu archive: %s\n", opts->archive); }
}

/* file name processing: we update the file list and count variables here, if there are no files we exit */
if ( !opts->print_processed_list && !opts->menu && !opts->resealhottracklist && !opts->purgehottracklist ) {
	int i;
	struct stat sb;
	char *entry;
	cpdu_file_type ft;

	for(i=0;opts->argv[i];i++) {
		archive_access_error(opts->argv[i]);
				
		{ int r; r = access(opts->argv[i], R_OK|W_OK); if ( r == -1 ) { merror("insufficient permissions on file %s: %s\n", opts->argv[i], strerror(errno)); continue; } }
		
		if ( stat(opts->argv[i], &sb) == -1 )
		{ 
			merror("%s: %s\n", opts->argv[i], strerror(errno));
			if ( opts->doarchive ) { merror("could not continue archive operation. Terminating.\n"); exit(0); }
			continue;
		}
		else
		{
		if ( !S_ISDIR(sb.st_mode) ) {
		{session_total_size += sb.st_size;}
		/* update session state size measured in bytes */
		{ static int n = 0; if ( n == 0 ) { topentry = opts->argv[i]; n = 1; } }
		}
		

{ static char n = 0; char *entry = opts->argv[i]; int nn;
if ( n == 0 ) { largest_entry_size = strlen(entry); n = 1; }
else {
if ( (nn=strlen(entry)) > largest_entry_size ) largest_entry_size = nn;
}
}
				
#if 0
		if ( ciphermode == CIPHER_MODE_ENCRYPT && strstr(opts->argv[i], make_myrecoverdir()) ) {
			merror("tring to encrypt a file in the recovery database. skipping file.\n");
			continue;
		} else {
			char *svl = strdup(get_current_dir_name()), *pragma;
			chdir("..");
			pragma = strdup(get_current_dir_name());
			if ( strstr(pragma, make_myrecoverdir()) ) {
				merror("tring to encrypt file in the recovery database. skipping file.\n");
				chdir(svl); free(svl); free(pragma);
				continue;
			}
			chdir(svl); free(svl); free(pragma);
		}
#endif
		if ( chmod(opts->argv[i], sb.st_mode) == -1 ) {
			merror("insufficient permissions: %s: %s\n", opts->argv[i], strerror(errno));
			continue;
		}

		{ FILE *f;
			f = fopen(opts->argv[i], "rw");
			if ( !f && !(S_ISDIR(sb.st_mode)) ) {
				merror("insufficient permissions on file %s\n", opts->argv[i]);
				continue;
			}
		fclose(f);
		}

		if ( (ciphermode == CIPHER_MODE_DECRYPT) && !S_ISDIR(sb.st_mode) )
		{
			ft = cpdu_query_file_type (opts->argv[i]);
			if ( ft == cpdu_none ) {
				merror("file not encrypted: %s\n", opts->argv[i]);
                continue;
			} else if ( ft == cpdu_archive ) {
				archivelist = (char**) realloc(archivelist, archivelist_size +=sizeof(char*));
				archivelist[archivelist_count] = strdup(opts->argv[i]);
				archivelist_count++;
				continue;
			} else if ( ft == cpdu_encrypted ) {
				filecount++;
			} else if ( ft == cpdu_backup_archive ) {
				archivelist = (char**) realloc(archivelist, archivelist_size +=sizeof(char*));
				archivelist[archivelist_count] = strdup(opts->argv[i]);
				archivelist_count++;
                got_backup_archive = 1;
				continue;
            }
		}
		} /* else if stat */

	if ( ciphermode == CIPHER_MODE_ENCRYPT && !S_ISDIR(sb.st_mode) ) {
		if ( opts->rmrpath ) {
		static int* n;
		rmrpathlist = realloc(rmrpathlist, rmrpathlistsz+=sizeof(int*));
		n = malloc(sizeof(int));
		*n = i;
		rmrpathlist[rmrpathcount++] = n;
		}
		filecount++;
	}

	if ( S_ISDIR(sb.st_mode) ) {
	{ char *n; n = clf_strip_path_dlmtr(opts->argv[i]); if( n ) opts->argv[i] = n; }

	/* specify the 'topdir' variable for removing the archive directories correctly and also */
	{ static int n = 0; if ( n == 0 ) { topdir = opts->argv[i]; n = 1; }
		if ( opts->autonamearchive ) {
		char* n = (char*) malloc(strlen(topdir)+strlen(get_archive_ext())+1);
		strcpy(n, topdir);
		strcpy(n+strlen(topdir), get_archive_ext());
		strcat(n, "\0");
		opts->archive = n;
		}
	}

	{ int r; r = access(opts->argv[i], R_OK|W_OK|X_OK); if ( r == -1 ) { merror("permissions error: %s: %s\n", opts->argv[i], strerror(errno)); continue; } }
	}

	entrylist = (char**) realloc(entrylist, entrylist_size+=sizeof(char*));
	entrylist[entrylist_count] = strdup(opts->argv[i]);
	entrylist_count++;

	if ( S_ISDIR(sb.st_mode) ) {
		if ( opts->rmrpaths ) rmrpathsnoe++;
		getdir(strdup(opts->argv[i]),opts->recurse);
	} else { 

	}

} /* for */

	if ( !topdir ) {
	/* specify here the code for autonaming the archive */
		if ( opts->autonamearchive ) {
		char* n = (char*) malloc(strlen(topentry)+strlen(get_archive_ext())+1);
		strncpy(n, topentry, strlen(topentry));
		strcpy(n+strlen(topentry), get_archive_ext());
		strcat(n, "\0");
		opts->archive = n;
		}
	}

/* for data encryption mode */
	entrylist = (char**) realloc(entrylist, entrylist_size+=sizeof(char*));
	entrylist[entrylist_count] = NULL;
	listcounter=0;
	entrycounter=0;
	if ( archivelist ) {
		archivelist = (char**) realloc(archivelist, archivelist_size +=sizeof(char*));
		archivelist[archivelist_count] = NULL;
		archivecounter = 0;
	}

		/* check to see first if there are files to process, if not we print message and exit */
	if ( !filecount && !archivelist_count) {
	//merror("nothing to do");
	status_print_session_done();		
	opts->destructor(opts); if ( cipherctx ) freeCipherContext(cipherctx); close_system(); exit(0);
	}

}

if ( opts->backup ) goto _do_n_backup;
if ( got_backup_archive ) goto _backup;

/* the keydata retrieval */
if ( opts->commit_key ) secure_commit_key();

if ( !opts->keylist && !opts->commit_key ) {
	if ( opts->slkey ) {
		secure_local_key_get();
	}
	else if ( !opts->slkey && !opts->usekeyfile )
	{ int r;
		r = getpassword(ciphermode, "Passphrase:");
		if ( r == -1 ) { _secureclearpassbuf(); free(passbuf); free(passbufsz); opts->destructor(opts); if ( cipherctx ) freeCipherContext(cipherctx); close_system(); exit(0);
		}
	} else 	if ( ciphermode == CIPHER_MODE_ENCRYPT && opts->usekeyfile ) {
		int ret;
		passbuf = (unsigned char*) malloc(curkeysize);
		passbufsz = (unsigned long*) malloc(sizeof(unsigned long));
		*passbufsz = curkeysize;
		ret = read_key_from_keyfile(opts->keyfile, passbuf, curkeysize);
		if ( ret == -1 ) {
			merror("could not retrieve key from keyfile %s\n", opts->keyfile);
			opts->destructor(opts); if ( cipherctx ) freeCipherContext(cipherctx); close_system();
			exit(0);
		}
	}
}

	if ( ciphermode == CIPHER_MODE_ENCRYPT ) {
		int ret = 0;
		ret = addkey_to_masterkeylist(); /* adds the current passbuf */
		if ( ret != 0 ) {
			merror("WARNING: could not add key to master key list!: security error. aborting encryption session.\n");
			opts->destructor(opts); if ( cipherctx ) freeCipherContext(cipherctx); close_system(); exit(0);
		}
	}
	
/**/

    if ( opts->resealhottracklist && !passbuf ) {
            merror("you are trying to reseal the hot track session list without specifying a password. aborting the encrypion session.\n");
            exit(0);
    }

_do_n_archive:
_do_n_backup:
if ( opts->backup ) {
	char response='n',n=0;
#if 0
    fprintf(stderr, "Are You Sure Erase [%d] Files? [N/y]: ", entrylist_count);
	while(!n) {
		n = fgetc(stdin);
		n = tolower(n);
		if ( n == 'n' ) { fprintf(stderr, "\ncpdu: Exiting Program."); exit(0); }
		if ( n != 'y' ) { n = 0; continue; }
		if ( n == 'y' ) break;
	}
#endif
    n = 'y';
	if ( n == 'y' ) { char* backup_archive_name_string; int i; time_t log_time;
        time(&log_time);
        backup_archive_name_string = (char*) malloc(strlen(ctime(&log_time))+strlen(make_myrecoverdir())+1+1);
        strcpy(backup_archive_name_string, make_myrecoverdir());
        strcat(backup_archive_name_string, "/");
        strncat(backup_archive_name_string, ctime(&log_time), strlen(ctime(&log_time))-1);
        strcat(backup_archive_name_string, ".cpdu.backup");
        chmod_unsecure_file(make_mydir());
        chmod_unsecure_file(make_myrecoverdir());
        i = cpdu_archive_load(backup_archive_name_string);
        if ( i != -1 ) write_recovery_log(argc, argv);
       	chmod_secure_file(make_mydir());
        chmod_secure_file(make_myrecoverdir());	
        if ( i != -1 ) {
       	fprintf(stderr, "%d Files stored in %s within local cpdu recovery directory %s. The filename contains the session time and date.\n", entrylist_count, backup_archive_name_string, make_myrecoverdir());
        }
       	exit(1);
    }
    exit(1);
}

if ( opts->ciphermode == CIPHER_MODE_ENCRYPT && opts->menu ) {
entrylist = il;
entrylist_count = ilcnt;
entrylist_size = ilsz;
entrycounter = 0;
filecount = entrylist_count;
}

if ( opts->ciphermode == CIPHER_MODE_DECRYPT && opts->menu )
{
	entrylist = il;
	entrylist_count = ilcnt;
	entrylist_size = ilsz;
	filecount = entrylist_count;
	entrycounter = 0;
}

if ( opts->print_processed_list && ciphermode == CIPHER_MODE_DECRYPT ) {
	filecount = entrylist_count;
	entrycounter = 0;
}

if ( opts->resealhottracklist ) {
    filecount = entrylist_count;
    entrycounter = 0;
}

if ( ciphermode == CIPHER_MODE_ENCRYPT || ciphermode == CIPHER_MODE_DECRYPT )
{
    filecount = entrylist_count;
}

{ static char sv = 0;
if ((archivelist_count && ciphermode == CIPHER_MODE_DECRYPT && sv == 1) || ciphermode == CIPHER_MODE_ENCRYPT || ( ciphermode == CIPHER_MODE_DECRYPT && archivelist_count == 0 ) ) {
fprintf(stderr, "%s%sSession Started, /w %d File(s) to %s: Beginning Transform(s)...\n", ciphermode == CIPHER_MODE_ENCRYPT ? "Encryption" : "Decryption",  opts->doarchive ? " Package " : " ", archivelist_count && ciphermode == CIPHER_MODE_DECRYPT ? diff(archive_entry_status_list[asel_counter]->count, archive_entry_status_list[asel_counter]->dircount) : filecount, ciphermode == CIPHER_MODE_ENCRYPT ? "Encrypt" : "Decrypt");
} else if ( opts->backup ) {
fprintf(stderr, "Erase Session Started: Beginning to Secure Wipe File(s)...\n");
}
sv = 1;
}

_backup:

session_current_size = 0;

while(entrylist[entrycounter]||dostdin)
{
	FILE *in, *out;
	char* string;
	mode_t svdmode;

if ( dostdin ) {
	char fstdin[] = ".cpdu_stdin";
	int fd=0; fd = open(fstdin, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR|S_IXUSR);
	read_stdin_to_fd(fd);
	close(fd);
	curfile = &fstdin[0];
	chmod_unsecure_file(curfile);	
} else {

	if (entrylist[entrycounter]) {
		curfile = entrylist[entrycounter++];
	{ int r; struct stat sb; r = stat(curfile, &sb); if ( S_ISDIR(sb.st_mode) || r==-1 ) continue; }
	} else { break; }

}
	{ cpdu_file_type ft;
	ft = cpdu_query_file_type(curfile);
		if ( ft == cpdu_archive || ft == cpdu_backup_archive )
		continue;
	}
		

	stat(curfile, &statbuf);
	curfilesize = statbuf.st_size; if ( curfilesize == 0 ) continue;
	svdmode = statbuf.st_mode;

	if ( (ciphermode == CIPHER_MODE_ENCRYPT) && opts->registerrdb ) {
		int r;
		chmod(make_myrecoverdir(), S_IRUSR|S_IWUSR|S_IXUSR);
		char* rentry = mk_recoverdb_entry(curfile);
		r = copy_file(curfile, rentry);
			if ( r == -1 ) {
				merror("WARNING: could not copy file %s to recover database, aborting encryption\n", curfile);
				continue;
			}
		chmod_secure_file(make_myrecoverdir());
	}

	if ( opts->backup ) {
		wipefile(curfile);
		remove(curfile);
		continue;
	}

	{ int n = strlen(curfile)+10+4;
	string = (char*) malloc(n);
	strcpy(string, curfile);
	strcat(string, ".encrypted\0");
	curfileout = string;
	}

	if ( ciphermode == CIPHER_MODE_ENCRYPT && opts->zlib )
	{
	char mode[4];
	strcpy(mode, "wb");
	strncat(mode, opts->zlib_level_string, 1);
	strcat(mode,"\0");
	if ( file_compress(curfile, string, mode) == -1 ) {
		merror("could not compress file %s, aborting encryption.\n", curfile);
		continue;
	}
	rename(string, curfile);
	}

{ char bzdone = 0;
_bzreopen:

	in = fopen(curfile, "rm");
	if ( ferror(in) ) { merror("file open error on file %s: %s", curfile, strerror(errno)); continue;}
	out = fopen(string, "w");
	if ( ferror(out) ) { merror("file open error on file %s: %s", string, strerror(errno)); continue;}
	setvbuf(in, NULL, _IONBF, 0);
	setvbuf(out, NULL, _IONBF, 0);

	if ( ciphermode == CIPHER_MODE_ENCRYPT && opts->bzlib && !bzdone ) {
		size_t n; n = statbuf.st_size; bz_curfile = curfile; bz_curfile_size = statbuf.st_size; /* @ set bzip current filename */
		bz_compressStream ( in, out );
		rename(string, curfile);
		remove(string);
		stat(curfile, &statbuf); bz_curfile_size = statbuf.st_size;
	   	session_total_size -= curfilesize; session_total_size += bz_curfile_size;
   		bzdone = 1; goto _bzreopen;		
    }

}

	stat(curfile, &statbuf);
	curfilesize = statbuf.st_size;

	cipher_block_mode = CIPHER_MODE_CBC;
//		{session_total_size += sb.st_size;}
if ( ciphermode == CIPHER_MODE_DECRYPT )
{	
	int n = decrypt_header(in);
	if ( n == -1 ) { fclose(in); fclose(out); remove(string); fprintf(stderr, "\n"); continue; }

	rwoffset = init_file_decrypt(cipherctx, in, out); session_total_size -= rwoffset;
		if ( rwoffset == -1 ) { fclose(in); fclose(out); remove(string); fprintf(stderr, "\n"); continue; }
	cipher_block_mode = CIPHER_MODE_CBC;
	(*pCreateWorkContext)(cipherctx, passbuf, *passbufsz, CIPHER_MODE_DECRYPT, initcbcblock, NULL, NULL);
}
else
{ static int cwc = 0;
	if ( !cwc )
	(*pCreateWorkContext)(cipherctx, passbuf, *passbufsz, CIPHER_MODE_ENCRYPT, initcbcblock, &get_random_bytes, NULL);
	else
	(*pResetWorkContext)(cipherctx, CIPHER_MODE_ENCRYPT, initcbcblock, &get_random_bytes, NULL);
	cwc = 1;
	originalfilesize = curfilesize;
	rwoffset = init_file_encrypt(cipherctx, in, out); session_total_size -= rwoffset;
		if ( rwoffset == -1 ) { fclose(in); fclose(out); remove(string); fprintf(stderr, "\n"); continue; }
	rwoffset = encrypt_header(cipherctx, out);
	cipher_block_mode = CIPHER_MODE_CBC;
}

if ( !opts->progress )
fprintf(stderr, "%s", curfile);

{ int n;
	n = do_file_transform(cipherctx, in, out);
		if ( n == -1 ) {
			merror("\nerror transforming file %s\n", curfile);
			fclose(in); fclose(out);
			remove(string);
			dostdin = 0;
			continue;
		}
}

	fclose(in);
	fclose(out);

	if ( ciphermode == CIPHER_MODE_DECRYPT ) {
		unsigned char* ldg;
		ldg = sha1_get_file_hash(string);
		if ( memcmp(ldg, check_hash, SHA1_DIGESTSIZE) == 0 )
		{ } else {
			remove(string);
			merror("\n%s: plaintext file hashes do not match the file decryption result. the file hash stored in the file header was found to not match the decrypted ciphertext hash sum of the file %s that contains the original plaintext hash sum stored in the ciphertext header information.\n", curfile,  curfile);
			continue;
		}
	}

	if ( ciphermode == CIPHER_MODE_ENCRYPT && opts->wipe ) {
		normv_int = 1;
		wipefile(curfile);
	}

	rename(string, curfile);
	remove(string);

	if ( ciphermode == CIPHER_MODE_DECRYPT && decompress )
	{ int r;
	_retry_compress:
	if ( opts->zlib ) {
		r = file_uncompress(curfile);
		if ( r == -1 ) goto _retry_compress;
	}

	if ( opts->bzlib ) { struct stat sb;
	_retry_bz:
		in = fopen(curfile, "rm");
		if ( ferror(in) ) { merror("file open error on file %s: %s", curfile, strerror(errno)); continue;}
		out = fopen(string, "w");
		if ( ferror(out) ) { merror("file open error on file %s: %s", string, strerror(errno)); continue;}
		setvbuf(in, NULL, _IONBF, 0);
		setvbuf(out, NULL, _IONBF, 0);
		bz_curfile = curfile; bz_curfile_size = statbuf.st_size;
		bz_uncompressStream ( in, out );
		stat(string, &sb); if ( sb.st_size == 0 ) { merror("truncation detected\n"); goto _retry_bz; }
		rename(string, curfile);
		remove(string);
	}
	decompress = 0;
	opts->zlib = opts->bzlib = 0;
	}

	chmod(curfile, svdmode);	

	if ( dostdin ) {
		int fd; fd = open(curfile, O_RDONLY);
		write_fd_to_stdout(fd);
		close(fd);
		remove(curfile);
		dostdin = 0;
	}

if ( ciphermode == CIPHER_MODE_ENCRYPT && !opts->menu && !opts->resealhottracklist ) {
	{ char* string = NULL; char* path;
	
	if ( entrylist[entrycounter-1][0] != '/' ) {	
	path = getenv("PWD");
	string = (char*) malloc(strlen(path)+strlen(entrylist[entrycounter-1])+2);
	strcpy(string, path);
	strcat(string, "/");
	strcat(string, entrylist[entrycounter-1]);
	} else {
		string = (char*) malloc(strlen(entrylist[entrycounter-1])+1);
		strcpy(string, entrylist[entrycounter-1]);
	}
	strcat(string, "\0");
	add_to_processedlist(string);
	}
}

if ( ciphermode == CIPHER_MODE_ENCRYPT && opts->menu && !opts->resealhottracklist ) {
		add_to_processedlist(entrylist[entrycounter-1]);
}

	file_processed_count++;
	status_print_file_done();
	if ( !opts->progress_rhetm ) /*@*/
	fprintf(stderr, "\n");
} /* while */

    write_recovery_log(argc, argv);

	if ( entrycounter && opts->progress_rhetm )
	fprintf(stderr, "\n");
	
	if ( opts->doarchive && (ciphermode == CIPHER_MODE_ENCRYPT)) {
		if ( cpdu_archive_load(opts->archive) == -1 ) {
			merror("error loading archive %s with session files\n", opts->archive);
		}
	}

if ( (ciphermode == CIPHER_MODE_DECRYPT) && archivelist_count ) {
	static int counter=0, r;
	for(; counter < archivelist_count;) {
	if ( entrylist ) /* free the file names in the entry list */
	{ int i; for(i=0;i<entrylist_count;i++) free(entrylist[i]); entrylist[i] = NULL;
	entrylist = NULL;
	entrylist_size = 0;
	entrylist_count = 0;
	entrycounter = 0;
	}
		r = cpdu_archive_unload(archivelist[counter]);
		if ( r == -1 ) {
			merror("error unloading archive %s. aborting.\n", archivelist[counter]);
			counter++;
			continue;
		}
	counter++;
    if ( cpdu_query_file_type(archivelist[counter-1]) == cpdu_backup_archive ) continue;
    else
	goto _do_n_archive;
	}
}

if ( opts->purgehottracklist && entrycounter == 0 )
{
    char* filename; 
    filename = (char*) malloc(strlen(getenv("HOME"))+strlen(processedlist_filename)+1);
    strcpy(filename, getenv("HOME"));
    strcat(filename, processedlist_filename);
    remove(filename);
}

	/* free the entrylist a(-1) + e - E1 - a(=a) - - (o) + a1 +9o) - 1*/
	status_print_session_done();	
	chmod_secure_mykeydir();
	opts->destructor(opts);
	_secureclearpassbuf();
	freeCipherContext(cipherctx);
	close_system();

	return 0;
}
/*! -- main -- */

/* -- end main -- */

/* -- start cpdu.c functions -- */
void secure_commit_key()
{
	int i;
	unsigned char* buffer = (unsigned char*) malloc(curkeysize);
	passbuf = (unsigned char*) malloc(curkeysize);
	passbufsz = (unsigned long*) malloc(sizeof(unsigned long));
	for( i=0; i < 27; i++ ) {
	gather_random_fast(buffer, curkeysize);
	gather_random_fast(passbuf, curkeysize);
	crunch_key(buffer, curkeysize, passbuf, curkeysize);
	}
	*passbufsz = curkeysize;
}

unsigned char* sha1_get_file_hash(char* file)
{
	int n;
	PSHA1CTX shactx;
	FILE *fs;
	unsigned char* buffer;
	static unsigned char dg[SHA1_DIGESTSIZE];
	fs = fopen(file, "r");
		if (!fs) {
			merror("could not open file %s for digest: %s\n", file, strerror(errno));
			return NULL;
		}
	buffer = (unsigned char*) malloc(4096);
	if ( !buffer ) {
		merror("error allocating buffer for digest: %s\n", strerror(errno));
		fclose(fs);
		return NULL;
	}
	shactx = SHA1_Create();
	while ( ((n = fread(buffer, 1, 4096, fs)) != 0) && !ferror(fs) )
	{
		SHA1_Update(shactx, buffer, n);
	}
	if ( ferror(fs) ) {
		merror("error reading from %s stream: %s\n", file, strerror(errno));
		free(buffer);
		fclose(fs);
		return NULL;
	}

	SHA1_Final(dg, shactx);
	if ( ciphermode != CIPHER_MODE_DECRYPT )
	memcpy(check_hash, dg, SHA1_DIGESTSIZE);

	free(buffer);
	fclose(fs);
	return &dg[0];
}

#define ENCRYPT (cpdu_encrypt_hdr)
unsigned char *vencrypt;
size_t vsize;
size_t doff;

size_t encrypt_header(void *pctx, FILE* fs)
{
	size_t n = sizeof(size_t)+initcbcblocksize+SHA1_DIGESTSIZE+1;
	unsigned char* buf = (unsigned char*) malloc(n%curblocksize?n=n+curblocksize:n);
	cipher_block_mode = CIPHER_MODE_ECB;

	fwrite(ENCRYPT, 1, sizeof(ENCRYPT), fs);
	fwrite(vencrypt+sizeof(cpdu_encrypt_hdr), 1, SHA1_DIGESTSIZE, fs);
	fwrite(&curcode, 1, 1, fs);
	(*pEncryptBuffer)(pctx, vencrypt+sizeof(cpdu_encrypt_hdr)+SHA1_DIGESTSIZE+1, buf, n);

	fwrite(buf, 1, n, fs);

	return n+sizeof(cpdu_encrypt_hdr)+1+SHA1_DIGESTSIZE;
}

int decrypt_header(FILE* fs)
{
	size_t n; char hdr[sizeof(cpdu_encrypt_hdr)]; unsigned char* buf;
	PSHA1CTX shactx; int ret;
	WORD8 dg[SHA1_DIGESTSIZE], tempdg[SHA1_DIGESTSIZE];
	fread(hdr, 1, sizeof(cpdu_encrypt_hdr), fs);
	if ( strncmp(hdr, ENCRYPT, sizeof(ENCRYPT)) ) { merror("file not encrypted: %s", curfile); return -1; }
	fread(tempdg, 1, SHA1_DIGESTSIZE, fs);
	fread(&curcode, 1, 1, fs);
        codeset = 1;
        if ( cipherctx ) freeCipherContext(cipherctx);
        cipherctx = determineCipherContext(NULL);
        if ( initcbcblock ) free(initcbcblock);
        initcbcblocksize = curblocksize;
        initcbcblock = (unsigned char*) malloc(initcbcblocksize);
	n = sizeof(size_t)+initcbcblocksize+SHA1_DIGESTSIZE+1;
	n = n%curblocksize?n+curblocksize:n;
	buf = (unsigned char*) malloc(n);
	fread(buf, 1, n, fs);
	doff = n+sizeof(ENCRYPT)+1+SHA1_DIGESTSIZE;

	if ( opts->keylist ) {
		ret = getkey_from_masterkeylist(tempdg); /* FIXME: currently, we have no internal security mechanism for the master keylist */
		if ( ret != 0 ) {
			merror("could not retrieve key for file %s. key is not in the current master list. aborting decryption.\n", curfile);
			free(vencrypt);
			return -1;
		}
	}
	if ( opts->usekeyfile ) {
		int ret;
		if ( passbuf ) _secureclearpassbuf();
		passbuf = (unsigned char*) malloc(curkeysize);
		passbufsz = (unsigned long*) malloc(sizeof(unsigned long));
		*passbufsz = curkeysize;
		ret = read_key_from_keyfile(opts->keyfile, passbuf, curkeysize);
		if ( ret == -1 ) {
			merror("could not retrieve key from keyfile %s\n", opts->keyfile);
			free(vencrypt);
			return -1;
		}
	}
	shactx = SHA1_Create();
	SHA1_Update(shactx, passbuf, *passbufsz);
	SHA1_Final(dg, shactx);
	if ( memcmp(tempdg, dg, SHA1_DIGESTSIZE) == 0 ) {}
	else { merror("invalid password: %s", curfile); return -1; }

	cipher_block_mode = CIPHER_MODE_ECB;
	(*pCreateWorkContext)(cipherctx, passbuf, *passbufsz, CIPHER_MODE_DECRYPT, NULL, NULL, NULL);
	(*pDecryptBuffer)(cipherctx, buf, buf, n, NULL);
	n = sizeof(size_t)+initcbcblocksize+SHA1_DIGESTSIZE+1;
	vencrypt = (unsigned char*) malloc(n);
	memcpy(vencrypt, buf, n);
	vsize = n;
	return 0;
}

#define ENCRYPT (cpdu_encrypt_hdr)
size_t init_file_encrypt(void* pctx, FILE *in, FILE *out)
{
	size_t r=0, n=0;
	PSHA1CTX shactx;
	WORD8 dg[SHA1_DIGESTSIZE];

	shactx = SHA1_Create();
	SHA1_Update(shactx, passbuf, *passbufsz);
	SHA1_Final(dg, shactx);

	sha1_get_file_hash(curfile);

	vsize = n = sizeof(ENCRYPT)+sizeof(size_t)+initcbcblocksize+(SHA1_DIGESTSIZE*2)+1+1;
	vencrypt = (unsigned char*) malloc(n);
	memcpy(vencrypt, ENCRYPT, sizeof(ENCRYPT));
	memcpy(vencrypt+sizeof(ENCRYPT), dg, SHA1_DIGESTSIZE);
	vencrypt[sizeof(ENCRYPT)+SHA1_DIGESTSIZE] = curcode;
	if ( opts->bzlib )
	vencrypt[sizeof(ENCRYPT)+SHA1_DIGESTSIZE+1] = 2;
	else if ( opts->zlib )
	vencrypt[sizeof(ENCRYPT)+SHA1_DIGESTSIZE+1] = 1;
	else vencrypt[sizeof(ENCRYPT)+SHA1_DIGESTSIZE+1] = 0;
	memcpy(vencrypt+sizeof(ENCRYPT)+SHA1_DIGESTSIZE+1+1, initcbcblock, initcbcblocksize);
	memcpy(vencrypt+sizeof(ENCRYPT)+SHA1_DIGESTSIZE+1+1+initcbcblocksize, &curfilesize, sizeof(size_t));
	memcpy(vencrypt+sizeof(ENCRYPT)+SHA1_DIGESTSIZE+1+1+initcbcblocksize+sizeof(size_t), check_hash, SHA1_DIGESTSIZE);
	return r;
}

size_t init_file_decrypt(void* pctx, FILE* in, FILE* out)
{
	if ( vencrypt[0] > 0 ) decompress = 1; else decompress = 0;
	if ( vencrypt[0] == 1 ) opts->zlib = 1; else if ( vencrypt[0] == 2 ) opts->bzlib = 1;
	memcpy(initcbcblock, vencrypt+1, initcbcblocksize);
	memcpy(&originalfilesize, vencrypt+initcbcblocksize+1, sizeof(size_t));
	memcpy(check_hash, vencrypt+1+initcbcblocksize+sizeof(size_t), SHA1_DIGESTSIZE);
	free(vencrypt);
	return doff;
}

static int get_y_pos()
{
	struct termios tty;
	struct termios old_tty;
	char cpr[32];			 /* RATS: ignore (checked) */
	int ypos;
	int terminalfd;
	static char openc = 0;
	
	if (openc == 0 ) {
		FILE *fs;
		fs = fopen("/dev/tty", "rw"); fclose(fs);
		terminalfd = fileno(stderr);//fileno(fs);
		openc = 1;
	}
	
	tcgetattr(terminalfd, &tty);
	tcgetattr(terminalfd, &old_tty);
	tty.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(terminalfd, TCSANOW | TCSAFLUSH, &tty);
	write(terminalfd, "\033[6n", 4);
	memset(cpr, 0, sizeof(cpr));
	read(terminalfd, cpr, 6);	    /* RATS: ignore (OK) */
	tcsetattr(terminalfd, TCSANOW | TCSAFLUSH, &old_tty);

	return ypos;
}

int do_file_transform(void* pctx, FILE* in, FILE* out)
{
	struct timeval tv; struct timezone tz;
	time_t stmsec; suseconds_t stmusec;
	unsigned char *buf = NULL, *obuf = NULL, *sbuf = NULL;
	size_t bufsize = 4096, bytes=curfilesize, toread=bufsize, towrite=0, r=0, w=0, cr=0, cw=0, rresized=0, sv=0, cosw=0;
	unsigned long long i=0, j=0;
	

	if ( opts->progress ) {
	gettimeofday(&tv,&tz); 
	stmsec = tv.tv_sec; stmusec = tv.tv_usec;
	}

	buf = (unsigned char *) malloc(bufsize+curblocksize);
		if ( !buf ) {
			merror("could not allocate %d bytes from a secure heap", bufsize);
			return -1;
		}
	obuf = (unsigned char *) malloc(bufsize+curblocksize);
		if ( !obuf ) {
			merror("could not allocate %d bytes from a secure heap", bufsize);
			return -1;
		}

	if ( ciphermode == CIPHER_MODE_DECRYPT ) {
	curfilesize -= rwoffset;
	bytes = curfilesize;
	}

	r = bufsize;

	j = curfilesize;
	i=0;
	cw=0;
	sv = 0;

while ( bytes > 0 ) {

	_do_read:
	if ( ciphermode == CIPHER_MODE_ENCRYPT ) r = bufsize;

	if ( ciphermode == CIPHER_MODE_DECRYPT ) {
		r = bufsize;
		if ( bufsize % curblocksize )
		r += curblocksize;
		sv = r;
	}

	do {
	r = fread(buf, 1, r, in);
	} while ( r == -1 && errno == EINTR );

	{session_current_size += r;}
	
	if ( ciphermode == CIPHER_MODE_ENCRYPT )
	if ( !feof(in) && r < bufsize ) { fseek(in, 0, SEEK_SET); fseek(in, cr, SEEK_SET); goto _do_read; }

	if ( ciphermode == CIPHER_MODE_DECRYPT )
	if ( !feof(in) && r < sv ) { fseek(in, 0, SEEK_SET); fseek(in, cr, SEEK_SET); goto _do_read; }

	cr += r;
	i+=r;

	if ( ciphermode == CIPHER_MODE_ENCRYPT && r % curblocksize )
		r += curblocksize;

	if ( r == 0 ) break;

	if ( ferror(in) ) { merror("file read error: %s", strerror(errno)); return -1; }

	if ( ciphermode == CIPHER_MODE_ENCRYPT ) {
		(*pEncryptBuffer)(pctx, buf, obuf, r);
	} else
	if ( ciphermode == CIPHER_MODE_DECRYPT ) {
		int t; t = (r - curblocksize) % curblocksize;
		(*pDecryptBuffer)(pctx, buf, obuf, r, NULL);
		r = r - t;
	}

	if ( ciphermode == CIPHER_MODE_DECRYPT ) {
		if ( cw + r >= originalfilesize ) {
			r = originalfilesize-(cw);
			rresized = 1;
			i = j = 1;
		}
	}

	do {
	w = fwrite(obuf, 1, r, out);
	} while ( w == -1 && errno == EINTR );

	if ( ferror(out) ) { merror("file write error: %s", strerror(errno)); return -1; }

	cw+=w;

	if ( 1 )
	{
	static char sbuf[2000] = {' '};
	static char cbuf[2000] = {' '};
	static char ebuf[2000] = {' '};
	static unsigned long long percent;
	//static unsigned char *pb;
	static unsigned char pb[41], pb2[41];
	static unsigned long long spercent;
	static char lpcnt[10]; static char lpcnt2[10];
	char c, pc;
	static char modl[] = "-\|/-\|/";
	//{ static char n = 0; if ( n == 0 ) { pb = (char*) malloc(largest_entry_size+1); n = 1; } }
	//static char reset = 0;
	//{ int i; if ( reset = 0 ) { fprintf(stderr, "\r%s%s ", lpcnt, pb); for(i=0;i<largest_entry_size;i++) fprintf(stderr, " "); } reset = 1; }
	pb[0] = '('; pb2[0] = '(';
	pb[39] = ')'; pb2[39] = ')';
	pb[40] = '\0'; pb2[40] = '\0';
	memset(pb+1, ' ', 38);
	memset(pb+1, ciphermode == 1 ? '+' : '-', i*38/j);
	percent = i*100/j;
	if ( percent > 100 ) percent = 100;
//	{/* set percent bar for total file progress for session */
	//spercent = session_current_size*100/session_total_size; if ( spercent == 99 || spercent > 100 ) spercent = 100;
	//if ( entrycounter == entrylist_count ) spercent = 100;
	//memset(pb2+1, ' ', 38);
	//if ( spercent != 100 ) memset(pb2+1, ciphermode == 1 ? '#' : '#', session_current_size*38/session_total_size); if ( spercent == 100 ) memset(pb2+1, ciphermode == 1 ? '+' : '-', 38);
//	}
	//{ static char cpercent[6]; sprintf(cpercent, "%d%c|\0", (int) percent, '%');
	//{ int i; for(i=0;i<6;i++) { pb[i] = cpercent[i]; } }
	//fprintf(stderr, "                                                                                                           ");
	//sprintf(sbuf, "\r                                                     \r|%d%c|%s : %s\0", (int) percent, '%', pb, curfile);
	//fprintf(stderr, "%s", sbuf);
	//sprintf(sbuf, "                                                          \r%s\r|%s\0", pb, curfile);
	char spcstr[3]; char spcstr2[3]; if ( percent < 10 ) sprintf(spcstr, "  \0"); if ( percent == 10 || percent > 10 ) sprintf(spcstr, " \0"); if ( percent == 100 ) sprintf(spcstr, "\0");
	//if ( spercent < 10 ) sprintf(spcstr2, "  \0"); if ( spercent == 10 || spercent > 10 ) sprintf(spcstr2, " \0"); if ( spercent == 100 ) sprintf(spcstr2, "\0");
	{ sprintf(lpcnt, "(%d%c%s)\0", (int) percent, '%', spcstr); }
	// sprintf(lpcnt2, "(%d%c%s)\0", (int) spercent, '%', spcstr2); }
//	}
	
	  c += 1; c = c % 8;
	  pc = modl[c];
	
		gettimeofday(&tv,&tz);
		stmsec = tv.tv_sec - stmsec; stmusec = tv.tv_usec - stmusec;
		stmsec = stmsec < 0 ? 0:stmsec; stmusec = stmusec < 0 ? 0:stmusec;
		//fprintf(stderr, "\r|%s||%d%c|%s %s |%d.%d|", opts->cipher, (int) percent, '%',pb, curfile, stmsec, stmusec);

	//{ static char *entry; static char n = 0; int i; if ( n == 0 ) { entry = (char*) malloc(largest_entry_size); memset(entry, ' ', largest_entry_size); strcat(entry, "\0"); n = 1; }
	{ int i; memset(cbuf, (int) ' ', largest_entry_size); cbuf[largest_entry_size] = '\0'; } //for(i=0;i<largest_entry_size+4;i++) strcat(stderr, " "); }

	#if 0 /* #(@)DEBUG: this is here so that we can print between two different lines at the same time and iterate them separately */
	{	static int fplpos=0; static char z = 0; if ( z == 1 ) { fplpos = get_y_pos(); }
		static int tfplpos=0; static char y = 0; if ( y == 0 ) { tfplpos = get_y_pos(); y = 1; }
		fprintf(stderr, "\033[%d;1H", tfplpos);
		fprintf(stderr, "\r%s %s%s ::Total File Progress::", lpcnt2, pb2);
		if ( z == 0 ) { fprintf(stderr, "\n"); z = 1; }
		
		{static char n = 0; if ( n == 1 ) fprintf(stderr, "\033[%d;1H", fplpos);
		
		n = 1;
		}
	
	} /*fplpos tfplpos*/
	#endif

	/* this seems to be a simple way to clear the current line for progress updates without the vertical cascade option from command line */
	if ( opts->progress_rhetm ) { int i;
		for(i=0;i<strlen(pb);i++) fputc(' ',stderr); for(i=0;i<strlen(lpcnt);i++) fputc(' ',stderr); for(i=0;i<strlen(opts->cipher);i++) fputc(' ',stderr);
		fputc(' ', stderr);
		for(i = 0;i < strlen(curfile); i++) fputc(' ',stderr);
	}
	
	fprintf(stderr, "\r%s%s(%s) %s", pb, lpcnt, opts->cipher, curfile);
	
	//sprintf(ebuf, "\r                                                                                                                                                                     \r%s%s %s\0", lpcnt, pb, curfile);
	//sprintf(sbuf, "                                                                                                    %s\0", ebuf);
	//sprintf(sbuf, "\r                                                                                                \r%s%s %s\0", lpcnt, pb, curfile);
	//sprintf(sbuf, "\r%s%s %s\0", lpcnt, pb, curfile);

	} /* opts->progress */
	
	bytes-=w;
}

	free(buf);
	free(obuf);
	return 0;
}

void status_print_file_done()
{
	if ( opts->progress && !opts->progress_rhetm && 0) /* FIXME: turned off for now */
	{
	static char sbuf[2000] = {' '};
	static char cbuf[2000] = {' '};
	static unsigned long long percent;
	static unsigned char pb[41];
	static unsigned long long spercent;
	static char lpcnt[7];
	pb[0] = '[';
	pb[39] = ']';
	pb[40] = '\0';
	memset(pb+1, ' ', 38);
	memset(pb+1, ciphermode == 1 ? '#' : '#', 38);
	percent = 100;
	spercent = 100;
	{ sprintf(lpcnt, "[%d%c]\0", (int) percent, '%'); }
	{ int i; memset(cbuf, (int) ' ', largest_entry_size); cbuf[largest_entry_size] = '\0'; }
	if ( opts->ciphermode == CIPHER_MODE_ENCRYPT ) {
	sprintf(sbuf, "\r%s  :%s%s [Compressed] [Encrypted], File Processing Done.\r: %s\0", cbuf, lpcnt, pb, curfile);
	} else {
	sprintf(sbuf, "\r%s  :%s%s [Decrypted] [DeCompressed], File Processing Done.\r: %s\0", cbuf, lpcnt, pb, curfile);
	}
	fprintf(stderr, "%s", sbuf);
	} /* opts->progress */
}

char **getdir(char *dirname, int recurse)
{
	struct dirent *direntt = NULL;
	DIR *dir = NULL;
	char *entry=NULL;
	struct stat sb;
	cpdu_file_type ft;

	stat(dirname, &sb);
	if ( chmod(dirname, sb.st_mode) == -1 ) {
			merror("insufficient permissions on directory: %s: %s\n", dirname, strerror(errno));
			return entrylist;
	}

	dir = opendir(dirname);
		if (!dir) {
			merror("could not open directory %s: %s", dirname, strerror(errno));
			goto _nullify_;
		}

	while(direntt = readdir(dir)) {
		if ( !strcmp(direntt->d_name, ".") || !strcmp(direntt->d_name, "..") )
				continue;

{ size_t len, i, n=0; char nbs=0;
		len = strlen(dirname)+strlen(direntt->d_name)+1;
		if ( (dirname[strlen(dirname)-1] != '/') ) { nbs = 1; len += 1; }
		entry = (char*) malloc(len); /* including null space */
		for (i = 0 ; i < strlen(dirname); i++)
			entry[i] = dirname[i];
		if ( nbs ) entry[i++] = '/';
		n+=i;
		for (i = 0 ; i < strlen(direntt->d_name); i++)
			entry[i+n] = direntt->d_name[i];
		n+=i;
		entry[n] = '\0';
}

	archive_access_error(entry);
	
	{ int r; r = access(entry, R_OK|W_OK); if ( r == -1 ) { merror("insufficient permissions on file %s\n", entry); free(entry); continue; }
	}


	
	stat(entry, &sb);

	if ( chmod(entry, sb.st_mode) == -1 ) {
			merror("insufficient permissions: %s: %s\n", entry, strerror(errno));
			free(entry);
			continue;
	}

//if ( !is_client ) {
if ( ciphermode == CIPHER_MODE_DECRYPT && !S_ISDIR(sb.st_mode) ) {
	ft = cpdu_query_file_type (entry);
	if ( ft == cpdu_none ) {
		merror("file not encrypted: %s\n", entry);
		free(entry);
		continue;
	} else if ( ft == cpdu_archive ) {
			archivelist = (char**) realloc(archivelist, archivelist_size +=sizeof(char*));
			archivelist[archivelist_count] = strdup(entry);
			archivelist_count++;
			continue;
    } else if ( ft == cpdu_backup_archive ) {
			archivelist = (char**) realloc(archivelist, archivelist_size +=sizeof(char*));
			archivelist[archivelist_count] = strdup(entry);
			archivelist_count++;
            got_backup_archive = 1;
			continue;
	}
}
//}
		entrylist = (char**) realloc(entrylist, entrylist_size +=sizeof(char*));
		entrylist[entrylist_count] = strdup(entry);
		entrylist_count++;

{ static char n = 0; char *nentry = entry ; int nn;
if ( n == 0 ) { largest_entry_size = strlen(nentry); n = 1; }
else {
if ( (nn=strlen(nentry)) > largest_entry_size ) largest_entry_size = nn;
}
}

		if ( S_ISDIR(sb.st_mode) ) {
		{ int r; r = access(entry, R_OK|W_OK|X_OK); if ( r == -1 ) { merror("insufficient permissions: %s\n", entry); free(entry); continue; } }
		if ( opts->rmrpaths ) rmrpathsnoe++;
		if ( recurse ) {
			getdir(strdup(entry), recurse);
		}
		} else {
			/* update session state size measured in bytes */
			{session_total_size += sb.st_size;}
			filecount++;
		}

	} /* while */

	closedir(dir);
	free(entry);

	_nullify_:
	return entrylist;
}

char **menu_getdir(char *dirname)
{
	struct dirent *direntt = NULL;
	static char *prev_dir = NULL;
	char *dir = NULL;	
	char* string = NULL;
	char* path = NULL;
	
	entrylist_count = 0;
	entrylist_size = 0;
	entrylist = (char**) malloc(sizeof(char**));
	entrylist_size += sizeof(char**);

	dir = opendir(dirname);
		if (!dir) { entrylist = NULL;
		goto _nullify_;
		}

	while(direntt = readdir(dir)) {
		entrylist = (char**) realloc(entrylist, entrylist_size+=sizeof(char*));
		entrylist[entrylist_count] = strdup(direntt->d_name);
		entrylist_count++;
	} /* while */

	closedir(dir);
	_nullify_:
	return entrylist;
}

int wipefile(char* file)
{
	unsigned char buffer[4096];
	int size, i=0, j, n;
	FILE *out;
	struct stat statbuf;

	stat(file, &statbuf);
	wpsz_int = size = statbuf.st_size;

	out = fopen(file, "r+");
	if ( !out || ferror(out) ) {
		merror("open failed on %s: %s", file, strerror(errno));
		return -1;
	}

	setvbuf(out, NULL, _IONBF, 0);
	wpdn_int = wpszdn_int = 0;
	for(j = 0; j<opts->wtimes; j++) {
		while ( size > 0 ) {
			i = gather_random_fast(buffer, 4096);
			do {
				n = fwrite(buffer, i, 1, out);
				fflush(out);
				fsync(fileno(out));
			} while ( n == -1 && errno == EINTR );
			fflush(out);
			size -= i;
			wpszdn_int+=i;
		}
		wpdn_int++;
		rewind(out);
	}

	fclose(out);
}

void _securereadpassbuf(int fd)
{
	int i=0;
	int *r;
	unsigned char *n;
	r = (int*) malloc(1);
	n = (unsigned char*) malloc(1);
	passbufsz = (unsigned long*) malloc(sizeof(unsigned long));
	passbuf = NULL;
	*passbufsz = 0;
	do {
		do {
			*r = read(fd, n, 1);
		} while ( *r == -1 && errno == EINTR );
		if ( *r != 1 ) continue;
		if ( *n == '\n') { if ( *passbufsz == 0 ) { passbuf = (unsigned char*) malloc(1); memset(passbuf, 0x00, 1); } break; }
		*passbufsz+=1;
		if ( !passbuf )
			passbuf = (unsigned char*) malloc(1);
		else
			passbuf =  (unsigned char*) realloc(passbuf, *passbufsz);		
		passbuf[*passbufsz-1] = *n;
	} while (1);
	free(r);
	free(n);
}


int ttyfd;
struct termios initialrsettings;
int _getpassword(char* prompt)
{
	struct termios newrsettings;
	ttyfd=open("/dev/tty",O_RDONLY);
		if ( ttyfd == -1 ) {
			merror("could not open /dev/tty for reading: %s", strerror(errno));
			return -1;
		}
	tcgetattr(ttyfd, &initialrsettings);
	newrsettings = initialrsettings;
	newrsettings.c_lflag &= ~ECHO;
	if(tcsetattr(ttyfd, TCSAFLUSH, &newrsettings) != 0) {
		merror("Could not set /dev/tty attributes");
		return -1;
	} else {
		fprintf(stderr, "%s", prompt);
		_securereadpassbuf(ttyfd);
		tcsetattr(ttyfd, TCSANOW, &initialrsettings);
	}
	close(ttyfd);
	return 0;
}

int getpassword(int cmode, char *prompt)
{
	struct termios newrsettings;
	int r=0;
	unsigned char *tbuf = NULL;
	unsigned long *tbsz = NULL;

	r = _getpassword(prompt);
		if ( r == -1 ) {
		memset(passbuf, 0xff, *passbufsz);
		memset(passbuf, 0xaa, *passbufsz);
		memset(passbuf, 0x55, *passbufsz);
		memset(passbufsz, 0xff, sizeof(unsigned long));
		memset(passbufsz, 0xaa, sizeof(unsigned long));
		memset(passbufsz, 0x55, sizeof(unsigned long));
		return -1;
		}

	if ( cmode == CIPHER_MODE_ENCRYPT ) {
		tbsz = (unsigned long*) malloc(sizeof(unsigned long));
		*tbsz = *passbufsz;
		tbuf = (unsigned char*) malloc(*passbufsz);
		memset(tbuf, 0x00, *tbsz);
		memcpy(tbuf, passbuf, *passbufsz);
		fprintf(stderr, "\r");
		fprintf(stderr,"Reenter ");
		r = _getpassword(prompt);
			if (r == -1) {
				goto error_;
			}
		if ( (*tbsz != *passbufsz) || (memcmp(passbuf, tbuf, *tbsz)) ) {
			r = -1;
			fputc('\n', stderr); merror("Passphrases do not match");
			goto error_;
		}
	}
	
	if ( *passbufsz < maxkeysize ) {
		passbuf = (unsigned char*) realloc(passbuf, maxkeysize);
		memset(passbuf+*passbufsz, 0x00, maxkeysize-*passbufsz);
	}

	goto return_;

	error_:
		_secureclearpassbuf();

	return_:
if(tbuf) {
		memset(tbuf, 0xff, *tbsz);
		memset(tbuf, 0xaa, *tbsz);
		memset(tbuf, 0x55, *tbsz);
		memset(tbuf, 0xff, *tbsz);
		memset(tbuf, 0xaa, *tbsz);
		memset(tbuf, 0x55, *tbsz);
		memset(tbuf, 0xff, *tbsz);
		memset(tbuf, 0xaa, *tbsz);
		memset(tbuf, 0x55, *tbsz);
		free(tbuf);
		free(tbsz);
}

{fprintf(stderr, "\n");}
	return r;
}

int write_fd_to_stdout(int fd_in)
{
	long bytes;
	unsigned int r, n;
	struct stat statbuf;
	unsigned char *buffer;
	int fd_out = fileno(stdout);

	buffer = (unsigned char *) malloc(4096);
	if ( !buffer ) {
		merror("could not allocate 4096 bytes from a secure heap");
		return -1;
	}

	fstat(fd_in, &statbuf);

	bytes = statbuf.st_size;

	while ( bytes > 0 ) {

	do {
		r = read( fd_in, buffer, 4096);
	} while ( r == -1 && errno == EINTR );
	if (r < 0) {
		merror("read from stdin support file failed: %s", strerror(errno));
		return -1;
	}

	bytes = bytes - r;

	do {
		n = write(fd_out, buffer, r);
	} while ( n == -1 && errno == EINTR );
	if (n < 0) {
		merror("write to stdout failed: %s", strerror(errno));
		return -1;
	}

	} /* while */

	free(buffer);
	return 0;
}

char *make_myrecoverdir()
{
	static char *home=NULL;
	static char dir[255] = {0};
	if ( !home ) {
		home = getenv("HOME");
		strcpy(dir, home);
		strcat(dir, "/.cpdu/.recoverdb");
		mkdir(dir, S_IRWXU|S_IRWXG|S_IRWXO);
		chmod(dir, S_IRWXU|S_IRWXG|S_IRWXO);
	}
	return dir;
}

char *rm_relative_path(char* name)
{
	char *s, *p;
	size_t n;
	struct stat sb;
	stat(name, &sb);
	if ( S_ISDIR(sb.st_mode) ) return name;
	s = strrchr(name, '/');
	if ( !s ) return name;
	n = strlen(s+1);
	p = (char *) malloc(n+1);
	strncpy(p, s+1, n);
	p[n] = '\0';
	return p;
}

char *clf_strip_path_dlmtr(char* name)
{
	int i;
	char *n;
	if ( strchr(name, '/') ) {
		n = (char*) malloc(strlen(name)-1+1);
		for (i=0;i<strlen(name)-1;i++) {
		n[i] = name[i];
		}
		n[i] = '\0';
	} else { return NULL; }
	return n;
}

char *mk_recoverdb_entry(char *pentry)
{
	char* nentry;
	char* entry;
	entry = rm_relative_path(pentry);
	nentry = (char*) malloc(strlen(make_myrecoverdir())+strlen(entry)+2);
	strncpy(nentry, make_myrecoverdir(), strlen(make_myrecoverdir()));
	strncpy(nentry+strlen(make_myrecoverdir()), "/", 1);
	strncpy(nentry+strlen(make_myrecoverdir())+1, entry, strlen(entry));
	nentry[strlen(make_myrecoverdir())+strlen(entry)+1] = '\0';
	{
		struct stat sb;
		char *dup, *o=NULL;
		int chgn=0;
		retry:
			chmod(nentry, S_IWUSR|S_IRUSR);
			if ( stat(nentry, &sb) == 0 ) {
				if ( chgn == 0 ) o = strdup(nentry);
				chgn++;
				dup = chgn ? o : strdup(nentry);
				nentry = (char*) realloc(nentry, strlen(nentry)+4);
				snprintf(nentry, strlen(nentry)+4,"%s(%d)\0", dup, chgn);
				if( o != dup ) { free(dup); dup = NULL; }
				goto retry;
			}
		if ( o ) free(o);
	}

	return nentry;
}

int copy_file(char *file, char* new)
{
	long bytes;
	unsigned int r, n;
	struct stat sb;
	unsigned char *buffer;
	int fd_in, fd_out;
	fd_in = open(file, O_RDONLY, S_IRUSR);
	fd_out = open(new, O_CREAT|O_WRONLY, S_IWUSR);
	if ( fd_in == -1 || fd_out == -1 ) {
		merror("could not open file %s for copying to %s: %s\n", file, new, strerror(errno));
		return -1;
	}

	buffer = (unsigned char *) malloc(4096);
	if ( !buffer ) {
		merror("could not allocate 4096 bytes from a secure heap");
		close(fd_in);
		close(fd_out);
		return -1;
	}

	fstat(fd_in, &sb);

	bytes = sb.st_size;

	while ( bytes > 0 ) {

	do {
		r = read(fd_in, buffer, 4096);
	} while ( r == -1 && errno == EINTR );
	if (r < 0) {
		merror("read from file %s failed: %s", file, strerror(errno));
		return -1;
	}

	bytes = bytes - r;

	do {
		n = write(fd_out, buffer, r);
	} while ( n == -1 && errno == EINTR );
	if (n < 0) {
		merror("write to file %s failed: %s", new, strerror(errno));
		return -1;
	}

	} /* while */

	free(buffer);
	close(fd_in);
	close(fd_out);
	chmod_secure_file(new);
	return 0;
}

int read_stdin_to_fd(int fd_out)
{
	long bytes;
	unsigned int r, n;
	struct stat statbuf;
	unsigned char *buffer;
	int fd_in = fileno(stdin);

	buffer = (unsigned char *) malloc(4096);
	if ( !buffer ) {
		merror("could not allocate 4096 bytes from a secure heap");
		return -1;
	}

	fstat(fd_in, &statbuf);

	bytes = statbuf.st_size;

	while ( bytes > 0 ) {

	do {
		r = read(fd_in, buffer, 4096);
	} while ( r == -1 && errno == EINTR );
	if (r < 0) {
		merror("read from stdin failed: %s", strerror(errno));
		return -1;
	}

	bytes = bytes - r;

	do {
		n = write(fd_out, buffer, r);
	} while ( n == -1 && errno == EINTR );
	if (n < 0) {
		merror("write to stdin support file failed: %s", strerror(errno));
		return -1;
	}

	} /* while */

	free(buffer);
	return 0;
}

char *make_mydir()
{
	static char *home=NULL;
	static char dir[255] = {0};
	if ( !home ) {
		home = getenv("HOME");
		strcpy(dir, home);
		strcat(dir, "/.cpdu");
		mkdir(dir, S_IRUSR|S_IWUSR|S_IXUSR);
	}
	return dir;
}

char *make_mykeydir()
{
	static char *home=NULL;
	static char dir[255] = {0};
	if ( !home ) {
		home = &dir[0];
		strcpy(dir, make_mydir());
		strcat(dir, "/.keystore");
		mkdir(dir, S_IRUSR|S_IWUSR|S_IXUSR);
	}
	return dir;
}

void chmod_unsecure_mykeydir()
{ 
	if ( -1 == chmod(make_mykeydir(), S_IRUSR|S_IWUSR|S_IXUSR) )
		merror("%s: could not change permissions\n", make_mykeydir());
}

void chmod_secure_mykeydir()
{
	if ( -1 == chmod(make_mykeydir(), 0) )
		merror("could not change the permissions of the local key directory\n");
}

void chmod_secure_file(char *file)
{
	chmod(file, 0);
}

void chmod_unsecure_file(char *file)
{
	if ( chmod(file, S_IRUSR|S_IWUSR|S_IXUSR) == -1 )
		merror("could not change read and write permissions on file %s: %s\n", file, strerror(errno));
}

void _secureclearpassbuf()
{
if ( passbuf ) {
memset(passbuf, 0xff, passbufsz ? *passbufsz : 0);
memset(passbuf, 0xaa, passbufsz ? *passbufsz : 0);
memset(passbuf, 0x55, passbufsz ? *passbufsz : 0);
memset(passbuf, 0xff, passbufsz ? *passbufsz : 0);
memset(passbuf, 0xaa, passbufsz ? *passbufsz : 0);
memset(passbuf, 0x55, passbufsz ? *passbufsz : 0);
memset(passbuf, 0xff, passbufsz ? *passbufsz : 0);
memset(passbuf, 0xaa, passbufsz ? *passbufsz : 0);
memset(passbuf, 0x55, passbufsz ? *passbufsz : 0);
}
if ( passbufsz ) {
memset(passbufsz, 0xff, sizeof(unsigned long));
memset(passbufsz, 0xaa, sizeof(unsigned long));
memset(passbufsz, 0x55, sizeof(unsigned long));
memset(passbufsz, 0xff, sizeof(unsigned long));
memset(passbufsz, 0xaa, sizeof(unsigned long));
memset(passbufsz, 0x55, sizeof(unsigned long));
memset(passbufsz, 0xff, sizeof(unsigned long));
memset(passbufsz, 0xaa, sizeof(unsigned long));
memset(passbufsz, 0x55, sizeof(unsigned long));
}
free(passbuf);
free(passbufsz);
passbuf = NULL;
passbufsz = NULL;
}

#if 0
char* getfile_from_recoverylist(char *digest)
{
	static char dgsv[SHA1_DIGESTSIZE];
	static char keyfile[200];
	static int isopen = 0;
	static FILE* f;
	int r;
	struct stat sb;

	if ( !isopen ) {
	strcpy(keyfile, make_mykeydir());
	strcat(keyfile, "/.masterkeylist");
	chmod(make_mykeydir(), S_IRUSR|S_IWUSR|S_IXUSR);
	r = stat(keyfile, &sb);
	if ( r == -1 ) {
		merror("could not stat master key list: %s\n", strerror(errno));
		chmod_secure_file(make_mykeydir());
		return -1;
	}
	chmod_unsecure_file(keyfile);
	f = fopen(keyfile, "r");
	}

	if ( isopen ) {
	int ret; ret = memcmp(dgsv, digest, sizeof(dgsv));
	if ( ret == 0 )
		return 0;
	}

	r = _seek_key(f, digest);
	if ( r != 0 ) {
		merror("did not find key in master key list\n");
		return 1;
	}

	passbufsz = (unsigned long*) malloc(sizeof(unsigned long));
	fread((unsigned char*)passbufsz, 1, sizeof(unsigned long), f);
	passbuf = (unsigned char*) malloc(*passbufsz);
	fread(passbuf, 1, *passbufsz, f);
	memcpy(dgsv, digest, sizeof(dgsv));
        if ( *passbufsz < maxkeysize ) {
                passbuf = (unsigned char*) realloc(passbuf, maxkeysize);
                memset(passbuf+*passbufsz, 0x00, maxkeysize-*passbufsz);
        }
	chmod_secure_file(keyfile);
	chmod_secure_file(make_mykeydir());
	isopen = 1;
	return 0;
}

int _seek_recover_list(FILE *f, char *digest)
{
	off_t r;
	unsigned long *sz;
	char buffer[SHA1_DIGESTSIZE];
	sz = (unsigned long*) malloc(sizeof(unsigned long));
	fseek(f, 0, SEEK_SET);
	do {
	fread(buffer, 1, SHA1_DIGESTSIZE, f);
	if ( feof(f) ){ free(sz); return 1; }
	if ( 0 == memcmp(buffer, digest, sizeof(buffer)) )
	{ free(sz); return 0; }
	else {
		fread((unsigned char*)sz, 1, sizeof(unsigned long), f);
		{ unsigned char* buf = malloc(*sz);	
		fread(buf, 1, *sz, f);
		free(buf);
		}
	} while (1);
	}
}

int addfile_to_recoverylist()
{
	WORD8 *dg;
	char file[200];
	strcpy(file, make_mydir());
	strcat(file, "/.recoverlist");
	dg = sha1_get_file_hash(curfile);
	FILE *f = fopen(file, "a");
	fclose(f);
	f = fopen(file, "r");
	if ( _seek_recover_list(f, dg) != 0 ) {
	fclose(f);
	f = fopen(keyfile, "a");
	fwrite(dg, 1, SHA1_DIGESTSIZE, f);
	fwrite((unsigned char*)passbufsz, 1, sizeof(unsigned long), f);
	fwrite(passbuf, 1, *passbufsz, f);
	}
	fclose(f);
	chmod_secure_file(keyfile);
	return 0;
}
#endif

int _seek_key(FILE *f, char *digest)
{
	off_t r;
	unsigned long *sz;
	char buffer[SHA1_DIGESTSIZE];
	sz = (unsigned long*) malloc(sizeof(unsigned long));
	fseek(f, 0, SEEK_SET);
	do {
	r = fread(buffer, 1, SHA1_DIGESTSIZE, f);
	if ( feof(f) ){ free(sz); return 1; }
	if ( 0 == memcmp(buffer, digest, sizeof(buffer)) )
	{ free(sz); return 0; }
	else {
		r = fread((unsigned char*)sz, 1, sizeof(unsigned long), f);
		{ unsigned char* buf = malloc(*sz);	
		r = fread(buf, 1, *sz, f);
		free(buf);
		}
	}
	} while (1);
}

int getkey_from_masterkeylist(char *digest)
{
	static char dgsv[SHA1_DIGESTSIZE];
	static char keyfile[200];
	static int isopen = 0;
	static FILE* f;
	int r;
	struct stat sb;

	if ( !isopen ) {
	strcpy(keyfile, make_mykeydir());
	strcat(keyfile, "/.masterkeylist");
	strcpy(masterkeydbfilename, keyfile);
	chmod(make_mykeydir(), S_IRUSR|S_IWUSR|S_IXUSR);
	r = stat(keyfile, &sb);
	if ( r == -1 ) {
		merror("could not stat master key list: %s\n", strerror(errno));
		chmod_secure_file(make_mykeydir());
		return -1;
	}
	chmod_unsecure_file(keyfile);
	f = fopen(keyfile, "r");
	}

	if ( isopen ) {
	int ret; ret = memcmp(dgsv, digest, sizeof(dgsv));
	if ( ret == 0 )
		return 0;
	}

	r = _seek_key(f, digest);
	if ( r != 0 ) {
		merror("did not find key in master key list\n");
		return 1;
	}

	passbufsz = (unsigned long*) malloc(sizeof(unsigned long));
	r = fread((unsigned char*)passbufsz, 1, sizeof(unsigned long), f);
	passbuf = (unsigned char*) malloc(*passbufsz);
	r = fread(passbuf, 1, *passbufsz, f);
	memcpy(dgsv, digest, sizeof(dgsv));
        if ( *passbufsz < maxkeysize ) {
                passbuf = (unsigned char*) realloc(passbuf, maxkeysize);
                memset(passbuf+*passbufsz, 0x00, maxkeysize-*passbufsz);
        }
	chmod_secure_file(keyfile);
	chmod_secure_file(make_mykeydir());
	isopen = 1;
	return 0;
}

int addkey_to_masterkeylist()
{
	PSHA1CTX shactx;
	WORD8 dg[SHA1_DIGESTSIZE];
	char keyfile[200];
	int r;
	strcpy(keyfile, make_mykeydir());
	strcat(keyfile, "/.masterkeylist");
	strcpy(masterkeydbfilename, keyfile);
	chmod(make_mykeydir(), S_IRUSR|S_IWUSR|S_IXUSR);
	chmod_unsecure_file(keyfile);
	shactx = SHA1_Create();
	SHA1_Update(shactx, passbuf, *passbufsz);
	SHA1_Final(dg, shactx);
	FILE *f = fopen(keyfile, "a");
	fclose(f);
	f = fopen(keyfile, "r"); setvbuf(f, NULL, _IONBF, 0);
	if ( _seek_key(f, dg) != 0 ) {
	fclose(f);
	f = fopen(keyfile, "a"); setvbuf(f, NULL, _IONBF, 0);
	r = fwrite(dg, 1, SHA1_DIGESTSIZE, f);
	r = fwrite((unsigned char*)passbufsz, 1, sizeof(unsigned long), f);
	r = fwrite(passbuf, 1, *passbufsz, f);
	}
	fclose(f);
	chmod_secure_file(keyfile);
	return 0;
}

void secure_local_key_set()
{
	struct stat statbuf;
	char slkeyfile[200];
	strcpy(slkeyfile, make_mykeydir());
	strcat(slkeyfile, "/.keyfile");
	chmod_unsecure_mykeydir();

	if ( stat(slkeyfile, &statbuf) == 0 ) {
		merror("secure local keyfile already exists, terminating...\n");
		close_system();
		opts->destructor(opts);
		exit(0);
	}

	fprintf(stderr,
		"- Secure Local Keyfile Passphrase Entry -\n"
		"Secure Local Key Directory: [%s]\n"
		"Secure Local Key File: [%s]\n",
		make_mykeydir(), slkeyfile
	);

	{ int r=0;
	r = getpassword(CIPHER_MODE_ENCRYPT, "Secure Local Key Phrase:");
	if ( r == -1 ) {
		r = 0;
		merror("could not retrieve password");
		_secureclearpassbuf();
		opts->destructor(opts);
		chmod_secure_mykeydir();
		close_system();
		exit(0);
	}
	}

	{ int fd, r;
		fd = open(slkeyfile, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR|S_IXUSR);
		r = write(fd, passbuf, *passbufsz);
		close(fd); fd = -1;
	}

	_secureclearpassbuf();
	chmod_secure_file(slkeyfile);
	chmod_secure_mykeydir();
	opts->destructor(opts);
	close_system();
}

void secure_local_key_get()
{ int fd, r; struct stat sb; char slkeyfile[200];
	strcpy(slkeyfile, make_mykeydir());
	strcat(slkeyfile, "/.keyfile\0");
	chmod_unsecure_file(make_mydir());
	chmod_unsecure_mykeydir();
	chmod_unsecure_file(slkeyfile);
	if ( stat(slkeyfile, &sb) == -1 ) { merror("secure local key file error: stat error: %s\n", strerror(errno));
	chmod_secure_file(slkeyfile);
	chmod_secure_mykeydir();
	opts->destructor(opts);
	close_system();
	exit(1);
	}
	passbufsz = (unsigned long*) malloc(sizeof(unsigned long));
	*passbufsz = sb.st_size;
	passbuf = (unsigned char*) malloc(*passbufsz);
	fd = open(slkeyfile, O_RDONLY);
	r = read(fd, passbuf, *passbufsz);

	if ( *passbufsz < maxkeysize ) {
		passbuf = (unsigned char*) realloc(passbuf, maxkeysize);
		memset(passbuf+*passbufsz, 0x00, maxkeysize-*passbufsz);
	}

	close(fd); fd = -1;
	chmod_secure_file(slkeyfile);
	chmod_secure_mykeydir();
}

#define new_archive_status_entry(ptr) { \
	ptr = (archive_entry*) malloc(sizeof(archive_entry)); \
	ptr->count = entrylist_count; \
	ptr->dircount = dircount; \
	ptr->name = larchive_name; \
	archive_entry_status_list = (archive_entry**) realloc(archive_entry_status_list, archive_entry_status_list_size+=sizeof(archive_entry)); \
	archive_entry_status_list[archive_entry_status_list_count++] = ptr; \
	}

int cpdu_archive_load(char* larchive_name)
{
	FILE* archive, *file;
	struct stat sb;
	int i, count;
	unsigned char buffer[4096];
	size_t size, r;
	int dircount = 0;
	PSHA1CTX shactx;
	WORD8 dg[SHA1_DIGESTSIZE];
	archive_entry *ars_entry;

	archive_name = larchive_name;

	if ( stat(archive_name, &sb) == 0 ) { merror("%s: archive already exists\n", archive_name); return -1; }

	archive = fopen(archive_name, "wb");

	r = fwrite(opts->backup ? cpdu_archive_backup_hdr : cpdu_archive_hdr, 1, opts->backup ? sizeof(cpdu_archive_backup_hdr) : sizeof(cpdu_archive_hdr), archive);

	if ( !opts->backup ) {
		shactx = SHA1_Create();
		SHA1_Update(shactx, passbuf, *passbufsz);
		SHA1_Final(dg, shactx);
		r = fwrite(dg, 1, SHA1_DIGESTSIZE, archive);
		r = fwrite(&curcode, 1, 1, archive);
	}

	count = entrylist_count - (opts->rmrpaths ? rmrpathsnoe : 0);

	r = fwrite(&count, 1, sizeof(int), archive);

	for(i=0;i < entrylist_count; i++) {
		size_t slen;
		static char *s;
		if ( stat(entrylist[i], &sb) == -1 ) continue;
		if ( opts->rmrpath ) {
			static int ce, cn=0;
			if ( cn < rmrpathcount)
			ce = *(rmrpathlist[cn]);
			if ( i == ce ) {
				s = rm_relative_path(entrylist[i]);
				cn++;
			} else { s = entrylist[i]; }
		} else if ( opts->rmrpaths ) {
			s = rm_relative_path(entrylist[i]);
			if ( S_ISDIR(sb.st_mode) ) continue;
		} else { s = entrylist[i]; } /* keep relative paths */
		slen = strlen(s);
		r = fwrite(&slen, 1, sizeof(size_t), archive);
		r = fwrite(s, 1, strlen(s), archive);
		if ( S_ISDIR(sb.st_mode) ) { dircount++; }
	}

	new_archive_status_entry(ars_entry)

	fprintf(stderr, "Package Archive %s: Deflating %d File(s), %d Directory(s)\nDeflating File(s)...\n", archive_name, diff(count,dircount), dircount);
	//fprintf(stderr, "deflating encrypted files into archive...", archive_name);
	//if ( opts->progress_rhetm ) fprintf(stderr, "\n");

	session_current_size = 0;
	for(i=0;i < entrylist_count;i++) {
		if ( stat(entrylist[i], &sb) == -1 ) { merror("could not stat file %s for archive: %s. aborting archive creation\n", entrylist[i], strerror(errno)); fclose(archive); remove(larchive_name); return -1; }
		if ( S_ISDIR(sb.st_mode) ) { if ( !opts->rmrpaths ) r = fwrite(&(sb.st_mode), 1, sizeof(mode_t), archive); continue; }
		file = fopen(entrylist[i], "rb");
		size = sb.st_size;
		r = fwrite(&(sb.st_mode), 1, sizeof(mode_t), archive);
		r = fwrite(&size, 1, sizeof(size_t), archive);
	fprintf(stderr, " deflating: %s\n", entrylist[i]);
	{ unsigned long long dn=0, td=size;	
		while( size > 0 ) {
			r = fread(buffer, 1, 1, file);
            if ( r == -1 || r == 0 ) { fseek(archive, dn, SEEK_SET); continue; }
			r = fwrite(buffer, 1, 1, archive);
            if ( r == -1 || r == 0 ) { fseek(archive, dn, SEEK_SET); continue; }
			size -= r;
			dn += r;
			session_current_size += r;
	if ( opts->progress )
	{
	static char sbuf[2000] = {' '};
	static char cbuf[2000] = {' '};
	static char ebuf[2000] = {' '};
	static unsigned long long percent;
	//static unsigned char *pb;
	static unsigned char pb[41], pb2[41];
	static unsigned long long spercent;
	static char lpcnt[10]; static char lpcnt2[10];
	char c, pc;
	static char modl[] = "-\|/-\|/";
	//{ static char n = 0; if ( n == 0 ) { pb = (char*) malloc(largest_entry_size+1); n = 1; } }
	//static char reset = 0;
	//{ int i; if ( reset = 0 ) { fprintf(stderr, "\r%s%s ", lpcnt, pb); for(i=0;i<largest_entry_size;i++) fprintf(stderr, " "); } reset = 1; }
	pb[0] = '('; pb2[0] = '(';
	pb[39] = ')'; pb2[39] = ')';
	pb[40] = '\0'; pb2[40] = '\0';
	memset(pb+1, ' ', 38);
	memset(pb+1, ciphermode == 1 ? '+' : '-', dn*38/td);
	percent = dn*100/td;
	if ( percent > 100 ) percent = 100;
	{/* set percent bar for total file progress for session */
	spercent = session_current_size*100/session_total_size; if ( spercent == 99 || spercent > 100 ) spercent = 100;
	memset(pb2+1, ' ', 38);
	if ( spercent != 100 ) memset(pb2+1, ciphermode == 1 ? '+' : '-', session_current_size*38/session_total_size); if ( spercent == 100 ) memset(pb2+1, ciphermode == 1 ? '+' : '-', 38);
	}
	//{ static char cpercent[6]; sprintf(cpercent, "%d%c|\0", (int) percent, '%');
	//{ int i; for(i=0;i<6;i++) { pb[i] = cpercent[i]; } }
	//fprintf(stderr, "                                                                                                           ");
	//sprintf(sbuf, "\r                                                     \r|%d%c|%s : %s\0", (int) percent, '%', pb, curfile);
	//fprintf(stderr, "%s", sbuf);
	//sprintf(sbuf, "                                                          \r%s\r|%s\0", pb, curfile);
	{ char spcstr[3]; char spcstr2[3]; if ( percent < 10 ) sprintf(spcstr, "  \0"); if ( percent == 10 || percent > 10 ) sprintf(spcstr, " \0"); if ( percent == 100 ) sprintf(spcstr, "\0");
	if ( spercent < 10 ) sprintf(spcstr2, "  \0"); if ( spercent == 10 || spercent > 10 ) sprintf(spcstr2, " \0"); if ( spercent == 100 ) sprintf(spcstr2, "\0");
	{ sprintf(lpcnt, "(%d%c%s)\0", (int) percent, '%', spcstr); }
	{ sprintf(lpcnt2, "(%d%c%s)\0", (int) spercent, '%', spcstr2); }
	}
	
	  c += 1; c = c % 8;
	  pc = modl[c];
#if 0	
		gettimeofday(&tv,&tz);
		stmsec = tv.tv_sec - stmsec; stmusec = tv.tv_usec - stmusec;
		stmsec = stmsec < 0 ? 0:stmsec; stmusec = stmusec < 0 ? 0:stmusec;
		//fprintf(stderr, "\r|%s||%d%c|%s %s |%d.%d|", opts->cipher, (int) percent, '%',pb, curfile, stmsec, stmusec);
#endif
	//{ static char *entry; static char n = 0; int i; if ( n == 0 ) { entry = (char*) malloc(largest_entry_size); memset(entry, ' ', largest_entry_size); strcat(entry, "\0"); n = 1; }
	{ int i; memset(cbuf, (int) ' ', largest_entry_size); cbuf[largest_entry_size] = '\0'; } //for(i=0;i<largest_entry_size+4;i++) strcat(stderr, " "); }

	#if 0 /* #(@)DEBUG: this is here so that we can print between two different lines at the same time and iterate them separately */
	{	static int fplpos=0; static char z = 0; if ( z == 1 ) { fplpos = get_y_pos(); }
		static int tfplpos=0; static char y = 0; if ( y == 0 ) { tfplpos = get_y_pos(); y = 1; }
		fprintf(stderr, "\033[%d;1H", tfplpos);
		fprintf(stderr, "\r%s %s%s ::Total File Progress::", lpcnt2, pb2);
		if ( z == 0 ) { fprintf(stderr, "\n"); z = 1; }
		
		{static char n = 0; if ( n == 1 ) fprintf(stderr, "\033[%d;1H", fplpos);
		
		n = 1;
		}
	
	} /*fplpos tfplpos*/
	#endif

	//memset(cbuf, ' ', largest_entry_size-strlen(curfile));
	//cbuf[largest_entry_size-strlen(curfile)] = '\0';
	//fprintf(stderr, "\r                                                                                                                                                                    ");
	{ static char *ccbuf; ccbuf = (char*) malloc(strlen(opts->cipher)+2+1); memset(ccbuf, ' ', strlen(opts->cipher)+2); ccbuf[strlen(opts->cipher)+2+1] = '\0';
	//fprintf(stderr, "                                                                                                  \r%s%s %s", pb, lpcnt, entrylist[i]);
	}
	
	//sprintf(ebuf, "\r                                                                                                                                                                     \r%s%s %s\0", lpcnt, pb, curfile);
	//sprintf(sbuf, "                                                                                                    %s\0", ebuf);
	//sprintf(sbuf, "\r                                                                                                \r%s%s %s\0", lpcnt, pb, curfile);
	//sprintf(sbuf, "\r%s%s %s\0", lpcnt, pb, curfile);

	} /* opts->progress */
	//else { fprintf(stderr, "%s\n", entrylist[i]); }
	}
		}
	//if ( opts->progress_piouemy ) fprintf(stderr, "\n");
	fclose(file);
	}

	//if ( opts->progress_rhetm ) fprintf(stderr, "\n");

	fprintf(stderr, "Package Archive '%s' Created.\n", larchive_name);
	
	fclose(archive);

return 0;
}


void print_archive_list(char* larchive_name)
{
	FILE* archive, *file;
	struct stat sb;
	int i, count;
	unsigned char buffer[4096], hdr[100];
	size_t size, r;
	int n;
	char c;
	char *entry;
	char *curdir;
	mode_t mode;
	char *dirlist;
	int isdir=0;
	int dircount=0;
	PSHA1CTX shactx;
	WORD8 dg[SHA1_DIGESTSIZE], tdg[SHA1_DIGESTSIZE];
	archive_entry *ars_entry;
    cpdu_file_type ft;

	archive_name = larchive_name;

	if ( stat(archive_name, &sb) == -1 ) { merror("%s: %s\n", archive_name, strerror(errno)); return -1; }

    ft = cpdu_query_file_type(archive_name);

	archive = fopen(archive_name, "rb");
	r = fread(hdr, 1, ft == cpdu_backup_archive ? sizeof(cpdu_archive_backup_hdr) : sizeof(cpdu_archive_hdr), archive);

	if ( ft != cpdu_backup_archive && ft != cpdu_archive ) {
		merror("file %s is not cpdu archive\n", archive_name);
		fclose(archive);
		return -1;
	}
	
	if ( ft == cpdu_archive) {
	r = fread(tdg, 1, SHA1_DIGESTSIZE, archive);
	r = fread(&curcode, 1, 1, archive);
	}
	r = fread(&count, 1, sizeof(int), archive);
	entrylist = (char**) malloc(sizeof(char*));

{
	size_t slen; int les = 0;
	entrylist_count = 0; entrylist_size = 0;
	do {
	r = fread(&slen, 1, sizeof(size_t), archive);
	entry = (char*) malloc(slen+1);
	if ( slen > les ) les = slen;
	r = fread(entry, 1, slen, archive);
	entry[slen] = '\0';
	entrylist_count++;
	fprintf(stderr, "[%d] %s\n", entrylist_count, entry);
//	entrylist = (char**) realloc(entrylist, entrylist_size+=sizeof(char*));
//	entrylist[entrylist_count] = entry;
	} while(entrylist_count<count);

#if 0
    i = 0;
{ char *cbuf; cbuf = (char*) malloc(les); memset(cbuf, ' ', les);
	do {
		n = 0;
		r = fread(&mode, 1, sizeof(mode_t), archive);
		r = fread(&size, 1, sizeof(size_t), archive);
		fseek(archive, size, SEEK_CUR);
		i++;

    } while( i < count );
}
#endif

}

	fprintf(stderr, "Package Archive '%s' is Intact with %d File(s) Encrypted and Compressed\n", larchive_name, count);
}



int cpdu_archive_unload(char* larchive_name)
{
	FILE* archive, *file;
	struct stat sb;
	int i, count;
	unsigned char buffer[4096], hdr[100];
	size_t size, r;
	int n;
	char c;
	char *entry;
	char *curdir;
	mode_t mode;
	char *dirlist;
	int isdir=0;
	int dircount=0;
	PSHA1CTX shactx;
	WORD8 dg[SHA1_DIGESTSIZE], tdg[SHA1_DIGESTSIZE];
	archive_entry *ars_entry;
	cpdu_file_type ft;

	archive_name = larchive_name;

	if ( stat(archive_name, &sb) == -1 ) { merror("%s: %s\n", archive_name, strerror(errno)); return -1; }

	ft = cpdu_query_file_type(archive_name);

	archive = fopen(archive_name, "rb");

	r = fread(hdr, 1, ft == cpdu_backup_archive ? sizeof(cpdu_archive_backup_hdr) : sizeof(cpdu_archive_hdr), archive);

	if ( ft != cpdu_backup_archive && ft != cpdu_archive ) {
		merror("file %s is not cpdu archive\n", archive_name);
		fclose(archive);
		return -1;
	}
	
	if ( ft == cpdu_archive ) {
	r = fread(tdg, 1, SHA1_DIGESTSIZE, archive);
	r = fread(&curcode, 1, 1, archive);

        codeset = 1;
        if ( cipherctx ) freeCipherContext(cipherctx);
        cipherctx = determineCipherContext(NULL);
        if ( opts->usekeyfile ) {
                int ret;
                if ( passbuf ) _secureclearpassbuf();
                passbuf = (unsigned char*) malloc(curkeysize);
                passbufsz = (unsigned long*) malloc(sizeof(unsigned long));
                *passbufsz = curkeysize;
                ret = read_key_from_keyfile(opts->keyfile, passbuf, curkeysize);
                if ( ret == -1 ) {
                        merror("could not retrieve key from keyfile %s\n", opts->keyfile);
                        free(vencrypt);
                        return -1;
                }
        }

	if ( opts->keylist && !opts->usekeyfile ) { int ret;
		ret = getkey_from_masterkeylist(tdg); /* FIXME: currently, we have no internal security mechanism for the master keylist */
		if ( ret != 0 ) {
			merror("could not retrieve key for archive %s. key is not in the current master list. aborting decryption.\n", archive);
			fclose(archive);
			return -1;
		}
	}
	shactx = SHA1_Create();
	SHA1_Update(shactx, passbuf, *passbufsz);
	SHA1_Final(dg, shactx);
	if ( memcmp(tdg, dg, SHA1_DIGESTSIZE) ) {
		merror("password for archive %s is incorrect\n", archive_name);
		fclose(archive);
		return -1;
	}
	} /* encrypted or just backup archive if__ */
	r = fread(&count, 1, sizeof(int), archive);
	entrylist = (char**) malloc(sizeof(char*));

	do {
	{
	size_t slen;
	r = fread(&slen, 1, sizeof(size_t), archive);
	entry = (char*) malloc(slen+1);
	r = fread(entry, 1, slen, archive);
	entry[slen] = '\0';
	entrylist = (char**) realloc(entrylist, entrylist_size+=sizeof(char*));
	entrylist[entrylist_count] = strdup(entry);
	filecount++;
	entrylist_count++;
	}

	/* we check here to see if any of the archives files already exist, if one does we abort processing the complete archive */
	n = stat(entrylist[entrylist_count-1], &sb);
	if ( n == 0 ) { merror("%s already exists, aborting archive operation\n", entrylist[entrylist_count-1]); return -1; }

{ static char n = 0; char *nentry = entry ; int nn;
if ( n == 0 ) { largest_entry_size = strlen(nentry); n = 1; }
else {
if ( (nn=strlen(nentry)) > largest_entry_size ) largest_entry_size = nn;
}
}

	} while(entrylist_count<count);

	i=0;

	fprintf(stderr, "Package Archive %s: Inflating %d files\nInflating File(s)...\n", archive_name, entrylist_count);

	fprintf(stderr, "inflating files from archive...\n", archive_name);
	//if(opts->progress_rhetm ) fprintf(stderr, "\n");

	do {
       		n = 0;
		r = fread(&mode, 1, sizeof(mode_t), archive);
		if ( S_ISDIR(mode) ) {
			curdir = entrylist[i];
			mkdir(curdir, mode);
			i++;
			dircount++;
			continue;
		}
		r = fread(&size, 1, sizeof(size_t), archive);
		fprintf(stderr, " inflating: %s\n", entrylist[i]);
	{
		char *dup, *o=NULL;
		int chgn=0;
		retry:
			if ( stat(entrylist[i], &sb) == 0 ) {
				if ( chgn == 0 ) o = strdup(entrylist[i]);
				chgn++;
				dup = chgn ? o : strdup(entrylist[i]);
				entrylist[i] = (char*) realloc(entrylist[i], strlen(entrylist[i])+4);
				snprintf(entrylist[i], strlen(entrylist[i])+4,"%s(%d)\0", dup, chgn);
				if( o != dup ) { free(dup); dup = NULL; }
				goto retry;
			}
		if ( o ) free(o);
	}
		file = fopen(entrylist[i], "wb");
			if ( !file ) {
				merror("in archive %s: file %s cannot be created: %s\n", archive_name, entrylist[i], strerror(errno));
				merror("aborting unloading archive %s\n", archive_name);
				fclose(archive);
				return -1;
			}
	{ unsigned long long dn = 0, td = size, tr = 0;
		while( size > 0 ) {
			//tr = (size - n) % 4096;
			r = fread(buffer, 1, 1, archive);
            if ( r == -1 || r == 0) { fseek(archive, dn, SEEK_SET); continue; }
            r = fwrite(buffer, 1, 1, file);
            if ( r == -1 || r == 0 ) { fseek(archive, dn, SEEK_SET); continue; }
			size -= r;
			n+=r;
			dn+=r;
			session_current_size += r;
	if ( opts->progress )
	{
	static char sbuf[2000] = {' '};
	static char cbuf[2000] = {' '};
	static char ebuf[2000] = {' '};
	static unsigned long long percent;
	//static unsigned char *pb;
	static unsigned char pb[41], pb2[41];
	static unsigned long long spercent;
	static char lpcnt[10]; static char lpcnt2[10];
	char c, pc;
	static char modl[] = "-\|/-\|/";
	//{ static char n = 0; if ( n == 0 ) { pb = (char*) malloc(largest_entry_size+1); n = 1; } }
	//static char reset = 0;
	//{ int i; if ( reset = 0 ) { fprintf(stderr, "\r%s%s ", lpcnt, pb); for(i=0;i<largest_entry_size;i++) fprintf(stderr, " "); } reset = 1; }
	pb[0] = '('; pb2[0] = '(';
	pb[39] = ')'; pb2[39] = ')';
	pb[40] = '\0'; pb2[40] = '\0';
	memset(pb+1, ' ', 38);
	memset(pb+1, ciphermode == 1 ? '+' : '-', dn*38/td);
	percent = dn*100/td;
	if ( percent > 100 ) percent = 100;
	{/* set percent bar for total file progress for session */
	spercent = session_current_size*100/session_total_size; if ( spercent == 99 || spercent > 100 ) spercent = 100;
	memset(pb2+1, ' ', 38);
	if ( spercent != 100 ) memset(pb2+1, ciphermode == 1 ? '+' : '-', session_current_size*38/session_total_size); if ( spercent == 100 ) memset(pb2+1, ciphermode == 1 ? '+' : '-', 38);
	}
	//{ static char cpercent[6]; sprintf(cpercent, "%d%c|\0", (int) percent, '%');
	//{ int i; for(i=0;i<6;i++) { pb[i] = cpercent[i]; } }
	//fprintf(stderr, "                                                                                                           ");
	//sprintf(sbuf, "\r                                                     \r|%d%c|%s : %s\0", (int) percent, '%', pb, curfile);
	//fprintf(stderr, "%s", sbuf);
	//sprintf(sbuf, "                                                          \r%s\r|%s\0", pb, curfile);
	{ char spcstr[3]; char spcstr2[3]; if ( percent < 10 ) sprintf(spcstr, "  \0"); if ( percent == 10 || percent > 10 ) sprintf(spcstr, " \0"); if ( percent == 100 ) sprintf(spcstr, "\0");
	if ( spercent < 10 ) sprintf(spcstr2, "  \0"); if ( spercent == 10 || spercent > 10 ) sprintf(spcstr2, " \0"); if ( spercent == 100 ) sprintf(spcstr2, "\0");
	{ sprintf(lpcnt, "(%d%c%s)\0", (int) percent, '%', spcstr); }
	{ sprintf(lpcnt2, "(%d%c%s)\0", (int) spercent, '%', spcstr2); }
	}
	
	  c += 1; c = c % 8;
	  pc = modl[c];
	#if 0
		gettimeofday(&tv,&tz);
		stmsec = tv.tv_sec - stmsec; stmusec = tv.tv_usec - stmusec;
		stmsec = stmsec < 0 ? 0:stmsec; stmusec = stmusec < 0 ? 0:stmusec;
		//fprintf(stderr, "\r|%s||%d%c|%s %s |%d.%d|", opts->cipher, (int) percent, '%',pb, curfile, stmsec, stmusec);
	#endif
	//{ static char *entry; static char n = 0; int i; if ( n == 0 ) { entry = (char*) malloc(largest_entry_size); memset(entry, ' ', largest_entry_size); strcat(entry, "\0"); n = 1; }
	{ int i; memset(cbuf, (int) ' ', largest_entry_size); cbuf[largest_entry_size] = '\0'; } //for(i=0;i<largest_entry_size+4;i++) strcat(stderr, " "); }

	#if 0 /* #(@)DEBUG: this is here so that we can print between two different lines at the same time and iterate them separately */
	{	static int fplpos=0; static char z = 0; if ( z == 1 ) { fplpos = get_y_pos(); }
		static int tfplpos=0; static char y = 0; if ( y == 0 ) { tfplpos = get_y_pos(); y = 1; }
		fprintf(stderr, "\033[%d;1H", tfplpos);
		fprintf(stderr, "\r%s %s%s ::Total File Progress::", lpcnt2, pb2);
		if ( z == 0 ) { fprintf(stderr, "\n"); z = 1; }
		
		{static char n = 0; if ( n == 1 ) fprintf(stderr, "\033[%d;1H", fplpos);
		
		n = 1;
		}
	
	} /*fplpos tfplpos*/
	#endif

	//memset(cbuf, ' ', largest_entry_size-strlen(curfile));
	//cbuf[largest_entry_size-strlen(curfile)] = '\0';
	//fprintf(stderr, "\r                                                                                                                                                                    ");
	{ static char *ccbuf; ccbuf = (char*) malloc(strlen(opts->cipher)+2+1); memset(ccbuf, ' ', strlen(opts->cipher)+2); ccbuf[strlen(opts->cipher)+2+1] = '\0';
	fprintf(stderr, "                                                                                          \r%s%s %s", pb, lpcnt, entrylist[i]);
	}
	//sprintf(ebuf, "\r                                                                                                                                                                     \r%s%s %s\0", lpcnt, pb, curfile);
	//sprintf(sbuf, "                                                                                                    %s\0", ebuf);
	//sprintf(sbuf, "\r                                                                                                \r%s%s %s\0", lpcnt, pb, curfile);
	//sprintf(sbuf, "\r%s%s %s\0", lpcnt, pb, curfile);

	} /* opts->progress */
	}
		}
		//if ( opts->progress_piouemy ) fprintf(stderr, "\n");
		fclose(file);
		chmod(entrylist[i], mode);
		i++;
	} while(i < count);

	new_archive_status_entry(ars_entry)

	//if ( opts->progress_rhetm ) fprintf(stderr, "\n");
	
	fprintf(stderr, "%d File(s), %d Directory(s) Extracted from Package Archive\n", diff(entrylist_count,dircount), dircount);
	fprintf(stderr, "Package Archive '%s' Extracted Correctly\n", larchive_name);

	fclose(archive);	
	return 0;
}

cpdu_file_type cpdu_query_file_type(char *file)
{
	cpdu_file_type ft = cpdu_none;
	size_t n;
	FILE *rd = fopen(file, "r");
	if ( rd == NULL ) {
		merror("coulnt determine file type for file %s: %s\n", file, strerror(errno));
		return cpdu_none;
	}

	char cpdu_archive_s[sizeof(cpdu_archive_hdr)];
	char cpdu_encrypted_s[sizeof(cpdu_encrypt_hdr)];
    char cpdu_backup_archive_s[sizeof(cpdu_archive_backup_hdr)];

#if 0
	{ unsigned char buffer[4096], n; size_t r; r = fread(buffer, 1, 4096, rd); n = is_base64_encoded(buffer, r);
		if ( n ) { fclose(rd); return cpdu_encrypted; } else { ft = cpdu_none; }
	}
	fseek(rd, 0, SEEK_SET);
#endif

	n = fread(cpdu_archive_s, 1, sizeof(cpdu_archive_hdr), rd);
		if ( strcmp(cpdu_archive_s, cpdu_archive_hdr) == 0 ) {
			ft = cpdu_archive;
		}
	fseek(rd, 0, SEEK_SET);
	n = fread(cpdu_encrypted_s, 1, sizeof(cpdu_encrypt_hdr), rd);
		if ( strcmp(cpdu_encrypted_s, cpdu_encrypt_hdr) == 0) {
			ft = cpdu_encrypted;
		}
	fseek(rd, 0, SEEK_SET);
	n = fread(cpdu_backup_archive_s, 1, sizeof(cpdu_archive_backup_hdr), rd);
		if ( strcmp(cpdu_backup_archive_s, cpdu_archive_backup_hdr) == 0) {
            ft = cpdu_backup_archive;
		}

	fclose(rd);
	return ft;
}

void cpdu_signal_sigint(int signal)
{
	fprintf(stderr, "\n");
	merror("signal SIGINT recieved. cleaning up and terminating...");
	curfile = strdup(curfile);
	if ( entrylist ) /* free the file names in the entry list */
	{ int i; for(i=0;i<entrylist_count;i++) if ( entrylist[i] ) free(entrylist[i]); }

	if ( normv_int ) {
		float sz = (float) wpsz_int, szdn = (float) wpszdn_int;
		fputc('\n', stderr);
		merror("the last file that was being processed, %s, has been wiped/written-over by %f percent", curfile, (float) (szdn*100/sz));
		if ( wpdn_int ) fprintf(stderr, ", %d times", (int) wpdn_int);
		fputc('\n', stderr);
		merror("the file was encrypted to %s however and you may retrieve plaintext data through normal decryption of this file\n", curfileout);
		free(curfile);
	} else {
	remove(curfileout);
	}
	chmod_secure_mykeydir();
	opts->destructor(opts);
	_secureclearpassbuf();
	freeCipherContext(cipherctx);
	close_system();

	fprintf(stderr, "done.\n");

	exit(1);
}

void status_print_session_done()
{
	if ( !opts->backup ) {
		if ( archivelist_count || opts->doarchive )
		{ int i; for(i=0;i<archive_entry_status_list_count;i++) {
					fprintf(stderr, "Package Archive '%s'; %d File(s), %d Directory(s) %s \n", archive_entry_status_list[i]->name, diff(archive_entry_status_list[i]->count, archive_entry_status_list[i]->dircount), archive_entry_status_list[i]->dircount, ciphermode == CIPHER_MODE_ENCRYPT ? "Deflated" : "Extracted");
				 }
		}
		fprintf(stderr, "%s Session Finished: %d File(s) %s\n", ciphermode == CIPHER_MODE_ENCRYPT ? "Encryption" : "Decryption", file_processed_count, ciphermode == CIPHER_MODE_ENCRYPT ? "Encrypted" : "Decrypted");
//		fprintf(stderr, "cpdu: %s [%s]",  ciphermode == CIPHER_MODE_ENCRYPT ? "Session Password commited to the Write Protected Master Key List Database." : "Session Key(s) Intact and Maintained in Write Protected Master Key List Database", masterkeydbfilename);
	}
}

#include "twofishctx_header.h" /* the twofish context is contained in the twofish.c file. we need to borrow it and restate it globally here */
#include "twofish.h"
void getrandombytes(WORD8* buffer, WORD32 size, void *nothing)
{
	gather_random_fast(buffer, size);
}
int generate_keyfile(char *keyfile, size_t fsize)
{
	int fd=0, i=0, ret=0;
	TWOFISHCTX *ctx=NULL;
	unsigned char *key=NULL;
	unsigned char *fbuf=NULL;
	unsigned char *initdata=NULL;
	unsigned int rounds=0;

	if ( fsize < TWOFISH_KEYSIZE ) {
		merror("the keyfile size specified is smaller than the\ntwofish algorithm keysize, it must be larger than 32 bytes");
		return -1;
	}

	ctx = (TWOFISHCTX*) smalloc(sizeof(TWOFISHCTX));
		if (!ctx) {
			merror("unable to allocate memory for cipher context");
			return -1;
		}
	memset(ctx, 0x00, sizeof(TWOFISHCTX));

	key = (unsigned char *) smalloc(TWOFISH_KEYSIZE);
		if ( !key ) {
			merror("unable to allocate memory for keyspace");
			goto _error_;
		}

	initdata = (unsigned char *) smalloc(sizeof(TWOFISH_BLOCKSIZE));
		if ( !key ) {
			merror("unable to allocate memory for cipher initdata");
			goto _error_;
		}

	fd = open(keyfile, O_WRONLY|O_CREAT|O_EXCL, S_IRUSR);
		if ( fd == -1 ) {
			merror("could not create keyfile %s: %s", keyfile,
strerror(errno));
			goto _error_;
		}

	gather_random_fast(key, TWOFISH_KEYSIZE);
	gather_random_fast(&rounds, sizeof(int));
	gather_random_fast(initdata, TWOFISH_BLOCKSIZE);
	rounds = rounds % 2;
	Twofish_CreateWorkContext(ctx, key, TWOFISH_KEYSIZE, CIPHER_MODE_ENCRYPT, initdata,
			(Cipher_RandomGenerator*)getrandombytes, NULL);

	fprintf(stderr, "Generating...");
{	
	char pb[41];
	unsigned long bufsiz=(fsize>4096?4096:fsize);
	unsigned long bytes=fsize;
	unsigned long r=0;
	unsigned int n=0;
	unsigned int sofar = 0, total = bytes;

	pb[0] = '[';
	pb[39] = ']';
	pb[40] = '\0';

	fbuf = (unsigned char *) smalloc(bufsiz+TWOFISH_BLOCKSIZE);
		if ( !fbuf ) {
			merror("could not allocate 4096 byte buffer");
			return -1;
		}

	while ( bytes > 0 ) {
	
	for(i=0;i<rounds;i++)
		Twofish_EncryptBuffer(ctx,key,key,TWOFISH_KEYSIZE);
	
	gather_random_fast(fbuf, bufsiz);
	Twofish_EncryptBuffer(ctx,fbuf,fbuf,bufsiz);

	if (r >= fsize-bufsiz)
		n = fsize-r;
	else
		n=bufsiz;
	
	do {
		n = write(fd, fbuf, n);
	} while ( n == -1 && errno == EINTR );
	if (n < 0) {
		merror("keydata write to keyfile %s failed: %s", keyfile, strerror(errno));
		return -1;
	}
	r+=n;
	bytes = bytes - n;

	sofar+=n;
	memset(pb+1, ' ', 38);
	memset(pb+1, '#', (int) sofar*38/total);
	fprintf(stderr,"\r[%d%c]%s %s Generating...", (int) sofar*100/total, '%', &pb[0], keyfile);
	} /* while */
	memset(fbuf, 0x00, bufsiz);
	sfree(fbuf);
}
	fprintf(stderr, "done.\n");

	goto _success_;

_error_:
	ret = -1;

_success_:
	if (ctx) {
		Twofish_DestroyWorkContext(ctx);
		sfree(ctx);
	}
	if ( initdata ) {
		memset(initdata, 0x00, TWOFISH_BLOCKSIZE);
		memset(initdata, 0x00, TWOFISH_BLOCKSIZE);
		memset(initdata, 0x00, TWOFISH_BLOCKSIZE);
		sfree(initdata);
	}
	if ( key ) {
		memset(key, 0x00, TWOFISH_KEYSIZE);
		memset(key, 0x00, TWOFISH_KEYSIZE);
		memset(key, 0x00, TWOFISH_KEYSIZE);
		sfree(key);
	}

	close(fd);

	return ret;
}

unsigned char *crunch_key(unsigned char *xkey, unsigned long xkeysize, unsigned char *keybuf, unsigned long outsize)
{
	static TWOFISHCTX *ctx=NULL;

	if ( !xkey )
		goto _return;

	if ( !ctx ) {
	ctx = (TWOFISHCTX*) smalloc(sizeof(TWOFISHCTX));
		if (!ctx) {
			merror("unable to allocate memory for cipher context");
			return NULL;
		}
	}
	initcbcblock = (unsigned char*) malloc(TWOFISH_BLOCKSIZE);
	cipher_block_mode = CIPHER_MODE_ECB;
	Twofish_CreateWorkContext(ctx, xkey, xkeysize, CIPHER_MODE_ENCRYPT, initcbcblock, &get_random_bytes, NULL);
	Twofish_EncryptBuffer(ctx, keybuf, keybuf, outsize);

	if ( ctx )
		Twofish_DestroyWorkContext(ctx);

	_return:

	return keybuf;
}

int read_key_from_keyfile(char *keyfile, unsigned char *keybuf, unsigned long keysize)
{
	int fd, i, bytes=0, r=0, n=0;
	unsigned char *buffer=NULL;
	unsigned char *key=NULL;
	struct stat statbuf;

	if ( !buffer )
		buffer = (unsigned char *) malloc(4096);
	if ( !buffer ) {
		merror("unable to allocate 4096 bytes from secure memory");
		return -1;
	}

	chmod_unsecure_file(keyfile);
	fd = open(keyfile, O_RDONLY);
		if ( fd == -1 ) {
			merror("could not open keyfile %s: %s", keyfile, strerror(errno));
			return -1;
		}

	if ( stat(keyfile, &statbuf) == -1 ) {
		merror("could not stat keyfile %s: %s", keyfile, strerror(errno));
		close(fd);
		return -1;
	}

	bytes = statbuf.st_size;

	memset(keybuf, 0, keysize);

	while ( bytes > 0 ) {
	do {
		n = read(fd, buffer, 4096);
	} while ( n == -1 && errno == EINTR );
	if ( n == -1 ) {
		merror("read from keyfile %s failed: %s", keyfile, strerror(errno));
		return -1;
	}
	key = crunch_key(buffer, n, keybuf, keysize);
	if ( !key ) {
		crunch_key(NULL,0,NULL,0);
		free(buffer);
		return -1;
	}
	bytes -= n;
	}

	free(buffer);
	crunch_key(NULL,0,NULL,0);
	close(fd);
	chmod_secure_file(keyfile);
	return 0;
}

#if 0
char *session_total_progress_string_update()
{
	static char sbuf[2000] = {' '};
	static unsigned long long percent;
	static unsigned char pb[51];
	pb[0] = '|';
	pb[49] = '|';
	pb[50] = '\0';
	memset(pb+1, ' ', 48);
	memset(pb+1, ciphermode == 1 ? '.' : '.', session_current_size*48/session_total_size);
	//percent = session_current_size*100/session_total_size;
	//if ( percent > 100 ) percent = 100;
	sprintf(sbuf, "%s\0", pb);
	return sbuf;
}
#endif

#if 0
char* get_archive_ext()
{
	long bytes;
	int r;
	struct stat sb;
	char buffer[2000] = {' '};
	char extfile[2000] = {' '};
	int exist = 0, fd;
	char *n;
	FILE *f;
	
	strcpy(extfile, make_mydir());
	strcat(extfile, "/");
	strcat(extfile, archive_ext_set_file);
	strcat(extfile, '\0');

	//fprintf(stderr, "\nextfile: %s\n", extfile);
	
	r = stat(extfile, &sb);
	if ( r == -1 ) {
		exist = 0;
	} else {
		exist = 1;
	}

	if ( !exist ) {
	fd = open(extfile, O_CREAT, S_IWUSR|S_IRUSR);
	close(fd);
	}

	if ( !exist ) {
	f = fopen(extfile, "w");
	fprintf(f, "%s", cur_ext);
	fclose(f);
	return cur_ext;
	}
	
	f = fopen(extfile, "r");
	fread(buffer, 1, sb.st_size, f);
	fclose(f);
	
	cur_ext = (char*) malloc(sb.st_size+1);
	
	memset(cur_ext, 0, sb.st_size+1);
	strncpy(cur_ext, buffer, sb.st_size);
	strcat(cur_ext, "\0");
	fprintf(stderr, "cur_Ext: %s", cur_ext);
	return cur_ext;
}
#endif

/* -- end cpdu.c functions -- */

