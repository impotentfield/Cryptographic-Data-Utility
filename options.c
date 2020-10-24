#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include "options.h"
#include "cipherdef.h"
#include "error.h"
#include "var.h"
#include "version.h"

void display_help(char *);
void display_version(void);

opts_t opts = NULL;

void parse_options_destroy(void *pobject)
{
	opts_t object = pobject;
	if (!object)
		return;
	if (object->argv)
		free(object->argv);
	free(object);
}

opts_t parse_options(int argc, char **argv)
{

	struct option long_options[] = {
		{"help", 0, 0, 'h'},
		{"version", 0, 0, 'V'},
		{"verbose", 0, 0, 'v'},
//		{"bzlib", 0, 0, 'j'},
		{"zlib", 0, 0, 'z'},
		{"wipe", 0, 0, 'w'},
		//{"stdin", 0, 0, 's'},
		{"recurse", 0, 0, 'r'},
		{"slkey", 0, 0, 'k'},
		{"slkeyset", 0, 0, 'S'},
		{"archive", 0, 0, 'a'},
		{"rmpath", 0, 0, 't'},
		{"rmapath", 0, 0, 'T'},
		{"cipher", 1, 0, 'c'},
		{"encrypt", 0, 0, 'e'},
		{"decrypt", 0, 0, 'd'},
		{"secure", 0, 0, 'f'},
		{"masterkey", 0, 0, 'm'},
		{"genkey", 1, 0, 'g'},
//		{"filekey", 1, 0, 'K'},
		{"sizekey", 1, 0, 'Z'},
		{"commitkey", 0, 0, 'x'},
	//	{"progress", 0, 0, 'p'},
		{"Archive", 1, 0, 'A'},
//		{"lineprogress", 0, 0, "P"},
	//	{"noprogress", 0, 0, "n"},
		{"archivelist", 1, 0, "i"},
		{"backup", 0, 0, 'B'},
		{"trackselect", 0, 0, 'H'},
		{"menu", 0, 0, 'u'},
	        {"sealtracklist", 0, 0, 'R'},
		{"purgetracklist", 0, 0, 'E'},
        //{"recoverselect", 0, 0, 'R'},
		{0, 0, 0, 0}
	};

	int option_index = 0;
	char *short_options = "h?Vedri:c:wzBEkSatTvmg:Z:xA:HuRf";
	int c, numopts;
	opts_t options;
	int gotarchivearg;
	char is_client_server = 0;

	if ( argc <= 1 ) {
		display_help(argv[0]);
		exit(0);
	}


	options = calloc(1, sizeof(*options));
	if (!options) {
		fprintf(stderr, "%s: option structure allocation failed (%s)", argv[0], strerror(errno));
		fprintf(stderr, "\n");
		return 0;
	}

	prog = argv[0];
	options->prog = argv[0];

	options->destructor = parse_options_destroy;

	options->argc = 0;
	options->argv = calloc(argc + 1, sizeof(char *));
	if (!options->argv) {
		fprintf(stderr, "%s: option structure argv allocation failed (%s)", argv[0], strerror(errno));
		fprintf(stderr, "\n");
		options->destructor(options);
		return 0;
	}

	numopts = 0;

	/* -- set default values */
	options->ciphermode = CIPHER_MODE_DECRYPT;
	options->cipher = "aes";
	options->zlib_level = 9;
	options->zlib_level_string = "9";
	options->log = 1;
	options->registerrdb = 1;
	options->progress = 0;
	options->progress_rhetm = 0;
	options->progress_piouemy = 1;
	options->wipe = 0;
	options->wtimes = 1;
	options->recurse = 0;

	do {
		c = getopt_long(argc, argv,
				short_options, long_options,
				&option_index);

		if (c < 0)
			continue;

		switch (c) {
		case '?':
		goto DisplayHelp;
		break;
		case 'h':
		DisplayHelp:
			display_help(argv[0]);
			exit(0);
		break;
#if 0
		case 'R':
			options->print_processedrecover_list = 1;
		break;
#endif
		case 'E':
			options->purgehottracklist = 1;
		break;
        case 'R':
            options->resealhottracklist = 1;
        break;
		case 'H':
			options->print_processed_list = 1;
		break;
		case 'u':
			options->menu = 1;
		break;
		case 'V':
			display_version();
			exit(0);
		break;
		case 'v':
//			options->verbose = atoi(optarg);
			options->verbose = 1;
		break;
//		case 'j':
//			options->bzlib = 1;
//		break;
		case 'm':
			options->keylist = 1;
		break;
		case 'e':
			options->ciphermode = CIPHER_MODE_ENCRYPT;
		break;
		case 'd':
			options->ciphermode = CIPHER_MODE_DECRYPT;
		break;
		case 'c':
			options->cipher = optarg;
		break;
		//case 's':
		//	options->rstdin = 1;
		//break;
		case 'z':
			options->zlib = 1;
		break;
		case 'k':
			options->slkey = 1;
		break;
		case 'N':
			options->log = 0;
		break;
		case 'r':
			options->recurse = 1;
		break;
		case 'S':
			options->slkeyset = 1;
		break;
		case 'a':
			options->autonamearchive = 1;
			options->doarchive = 1;
		break;
		case 't':
			options->rmrpath = 1;
		break;
		case 'T':
			options->rmrpaths = 1;
		break;
		case 'w':
			options->wipe = 1;
			options->wtimes = 15; //atoi(optarg); //#pragma: make 15 default
		break;
	        case 'f':
			options->registerrdb = 0;
		break;
		case 'g':
			options->genkeyfile = 1;
			options->keyfile = optarg;
		break;
//		case 'K':
//			options->usekeyfile = 1;
//			options->keyfile = optarg;
//		break;
//		case 'P':
//			options->progress = 1;
//			options->progress_piouemy = 0;
//			options->progress_rhetm = 1;
//		break;
		case 'n':
			options->noprogress = 1;
			options->progress = 0;
		break;
		case 'Z':
			options->gensize = atol(optarg);
			if ( options->gensize > 100000000 ) { merror("too many bytes for gen. data\n"); options->destructor(options); exit(0); }
		break;
		default:
			fprintf(stderr, "%s: Try '-?', '-h' or `--help' for more information.", argv[0]);
			fprintf(stderr, "\n");
			options->destructor(options);
			exit(0);
		break;
		case 'x':
			options->commit_key = 1;
		break;
		case 'A':
			options->doarchive = 1;
			options->archive = optarg;
		break;
		case 'i':
			options->listarchive = 1;
			options->archive = optarg;
		break;
		case 'B':
			options->backup = 1;
		break;
		}

	} while (c != -1);

	if ( options->ciphermode != CIPHER_MODE_DECRYPT && options->ciphermode != CIPHER_MODE_ENCRYPT && !options->genkeyfile && !options->slkeyset && !options->listarchive && !options->backup ) {
			fprintf(stderr, "%s: Please Specify the '--encrypt, -e' flag or the '--decrypt, -d' flag to Encrypt Data or Decrypt Data\n", argv[0]);
			fprintf(stderr, "%s: Try '-?', '-h' or `--help' for more information.", argv[0]);
			fprintf(stderr, "\n");
			options->destructor(options);
			exit(0);
	}


	if ( options->ciphermode == CIPHER_MODE_DECRYPT ) options->bzlib = options->zlib = 0;

	if ( options->bzlib && options->zlib ) { merror("specified zlib and bzlib compression for session. use one of each.\n"); exit(1); }
	if ( options->doarchive ) { options->recurse = 1; }
	if ( options->doarchive && (options->bzlib == 0 || options->zlib == 0) ) { options->zlib = 1; }
	if ( options->commit_key && (options->ciphermode == CIPHER_MODE_DECRYPT) ) { merror("you tried to use the -x, --commitkey option while in decryption mode\n"); exit(1); }
	if ( options->commit_key && (options->usekeyfile || options->slkey) ) { merror("you specified to use a random commit key for encryption while trying to use another encryption key option\n"); exit(1); }
	if ( options->keylist && (options->ciphermode == CIPHER_MODE_ENCRYPT) ) { merror("you tried to specify using the master key while in encryption mode\n"); exit(1); }
	if ( options->ciphermode == CIPHER_MODE_DECRYPT ) {
		if ( options->keylist && (options->usekeyfile || options->slkey) ) { merror("you specified using multiple key data options for decryption session\n"); exit(1); }
	}

	/* we make sure we have correct programmatic evaluation */
	if ( options->ciphermode == CIPHER_MODE_ENCRYPT ) {
		options->keylist = 0;
	}

	if ( options->genkeyfile && !options->gensize ) {
		merror("did not specify amount of random gen. data with the '-Z' flag\n");
		options->destructor(options);
		exit(0);
	}

	while (optind < argc) {
		options->argv[options->argc++] = argv[optind++];
	}

	return options;
}

#include "version.h"

void display_help(char *arg)
{
	fprintf(stderr,
		"Cryptographic Data Utility v%s\n"
		"Home: %s/.cpdu\n"
		"Usage: %s [OPTION] [-e, --encrypt FILE] [-d, --decrypt FILE] [-d, --decrypt ARCHIVE]"
		"\nOptions:\n"
		"-e, --encrypt,                encrypt mode\n"
		"-d, --decrypt,                decrypt mode, default\n"
		"-c, --cipher, 'cipher'        session cipher, default='aes'\n"
		"-r, --recurse,                recursive directory search\n"
//		"-s, --stdin,                  stdin, stdout\n"
		"-z, --zlib,                   zlib compression for archives or files\n"
//		"-j, --bzlib,                  bzlib compression for archives or files\n"
		"-A, --Archive, 'archive'      load or unload archive with session files. if string contains no appended . extension, .cpdu.package is appended. zlib compression is default.\n"
        	"-a, --archive,                load archive with session files. this option uses the first directory or filename for the archive string and .cpdu.package is appended. \
        	                               zlib compression is default.\n"
		"-i, --archivelist, 'archive'  print list of files within encrypted archive 'archive'\n"
		"-t, --rmpath,                 for archive, remove relative paths of single files on command line\n"
		"-T, --rmapath,                for archive, remove all relative paths of files\n"
		"-w, --wipe,                   wipe original copy(s) of encryption session file(s) with secure random numbers 15x/ovr after encryption\n"
/*
		"-K, --keyfile, 'file'         use 'file' for session key. TAKE NOTICE: the keyfile data will be code book block encrypted\n \
                                              as one data stream (each read is encrypted to return a continual encrypted key over each\n \
                                              read) and crunched the size of the current cipher's valid keylength and stored in\n \
                                              .masterkeylist with a valid cipher context keylength. the .masterkeylist copy of the key\n \
                                              and the keyfile used are both valid decryption keys for the encrypted file(s).\n"
*/
		"-S, --slkeyset,               local secure key set passphrase prompt\n"
		"-k, --slkey,                  local secure key for session\n"
		"-g, --genkey,      'file'     generate a secure keyfile with random character bytes using the secure random number generator device files\n"
		"-Z, --sizekey,     'bytes'    size of generated keyfile in bytes\n"
		"-x, --commitkey,              use a secure random key for encryption and commit the key to the .masterkeylist\n" 
		"-m, --masterkey,              get session decryption key(s) from exportable master key database\n"
//		"-P, --lineprogress,           progress mode without vertical cascade\n"
		//"-n, --noprogress,             do not show file progress updates\n"
		"-f, --secure                  allows secure mode during encryption. the files to be encrypted are not to be stored into recovery database\n"
		"-u, --menu                    show directory tree menu (starting at /home/{USER}' directory) to select which files to process for encryption/decryption\n"
	        "-H, --trackselect             All files over encryption sessions are stored in a list. Use this option to select and decrypt any file in the list or 'All' as an option\n"
        	"-R, --sealtracklist           encrypt all hottrack session files\n"
		"-E. --purgetracklist          decrypt all hottrack session files and remove the list (~/.cpdu_processedlist)\n"
		"-B, --backup                  backup files (plaintext and uncompressed) within archive in recoverydb. The archive name will contain the current time and date.\n"
	        "-V, --version,                show version and cipher info\n"
		"-h, --help,                   prints help\n",
CPDU_VERSION, getenv("HOME"), arg);
}

#if 0
void display_help(char *arg)
{
	fprintf(stderr,
		"Cryptographic Data Utility Cryptographic Package Distribution Utility v%s\n"
		"Home: %s/.cpdu\n"
		"Usage: %s [options] [-e, --encrypt files...] [-d, --decrypt files...] [-d, --decrypt [archives]...]"
		"\nOptions:\n"
		"--encrypt,     -e             encrypt mode\n"
		"--decrypt,     -d             decrypt mode, default\n"
		"--cipher,      -c 'cipher'    session cipher, default='aes/rijndael'\n"
		"--zlib,        -z             zlib compression for archives or files\n"
		"--bzlib,       -j             bzlib compression for archives or files\n"
		"--wipe,        -w             wipe original copy(s) of encryption session file(s) with secure random numbers 15x/ovr after encryption\n"
		"--Archive,     -A 'archive'   load or unload archive with session files (auto ext. enabled = '*.cpdu.pkg')\n"
        "--archive,     -a             load archive with session files (/w auto name feature, name archive /w first specified entry(file/dir) name /w ext. '*.cpdu.pkg')\n"
		"--archivelist, -i 'archive'   print list of files within encrypted archive 'archive'\n"
		"--rmpath,      -t             for archive, remove relative paths of single files on command line\n"
		"--rmapath,     -T             for archive, remove all relative paths of files\n"
		"--warchentry,  -W             wipe target archive directory(s) after archive is completed\n"
		"--keyfile,     -K 'file'      use 'file' for session key\n"
		"--slkeyset,    -S             local secure key set passphrase prompt\n"
		"--slkey,       -k             local secure key for session\n"
		"--keygen,      -g 'file'      generate a secure keyfile with random character bytes using the secure random number generator device files\n"
		"--keysize,     -Z 'bytes'     size of generated keyfile in bytes\n"
		"--keycommit,   -x             secure/hash low entropy key to full strength with random data and commit to keydb\n"
		"--masterkey,   -m             get session decryption key(s) from exportable master key database\n"
//		"--erase,       -E             erase/secure wipe files with prompt\n"
		"--secure,      -f             secure mode, disable file copying to the recover database registry directory\n"
		"--stdin,       -s             stdin, stdout\n"
		"--rhetm,       -P             progress mode without vertical cascade\n"
		"--noprogress,  -n             do not show file progress updates\n"
		"--verbose,     -v             verbose mode\n"
		"--version,     -V             show version and cipher info\n"
		"--help,        -h             prints help\n"
		"Server/Client Package/File Network Transfer General Options:\n"
		"Network Options:\n"
		"\t-p <n> port\n"
		"Server Options:\n"
	    "\t-L server mode\n"
		"\t-R keep the server running\n"
		"\t-M <n>\tmaximum amount of bytes we can receive\n"
		"Client Options:\n"
		"\t-l <ip>client mode with server's IPv4 address\n"
		"\t<files>files to send to the server\n\n",
CPDU_VERSION, getenv("HOME"), arg);
}
#endif
#include "version.h"
void display_version(void)
{
	fprintf(stderr,
			"Cryptographic Data Utility | Cryptographic Package Distribution Utility\n"
			" version %s\n"
			"Ciphers in CBC mode:          |Keysize|    |Blocksize|\n"
			" Aes/Rijndael (aes, rijndael)   32 256        16 128     (bytes/bits)\n"
			" Twofish      (tf, twofish)     32 256        16 128\n"
			" Blowfish     (bf, blowfish)    56 448         8 64\n"
			" Serpent      (spnt, serpent)   32 256        16 128\n"
			" Cast         (cast)            16 128         8 64\n"
			" Tripledes    (3des, des, tdes) 21 168         8 64\n"
			"Author: Richard Enciu - richardenciu@gmail.com\n",
			CPDU_VERSION);
}
