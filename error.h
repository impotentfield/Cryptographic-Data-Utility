/* error codes */
#define ERROR_INVALID_KEY			1
#define ERROR_FILE_NOT_ENCRYPTED	2
#define ERROR_INIT_FILE 			3

extern char *prog;
extern int my_errno;
extern char enl;

void merror(const char *fmt, ...);
