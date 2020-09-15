#
#
#
# cpdu for unix/linux #
#
#
#
VERSION = "0.49.6b"

CFLAGS = -O3 -g3 --no-warn
CC = gcc
prefix=/usr/local

OBJECTALL = cipher.o ciphervar.o error.o zlf.o options.o sha1.o sys_linux.o blowfish.o aes.o twofish.o tripledes.o serpent.o cast.o var.o bzf.o
#RM_OBJECT = rm_opts.o error.o sha1.o

all: cpdu status-make-cpdu-done
cpdu: libz.a status-make-zlib-done libbz2.a status-make-bzlib-done status-make-cpdu $(OBJECTALL)
	$(CC) $(CFLAGS) $(OBJECTALL) zlib/libz.a bzip2/libbz2.a cpdu.c -o cpdu -lncurses -lmenu

#rm: status-make-rm $(RM_OBJECT)
#	$(CC) $(CFLAGS) $(RM_OBJECT) rm.c -o cpdu_safe_copy -lncurses -lmenu

libbz2.a: status-make-bzlib
	make -C bzip2

libz.a: status-make-zlib
	make -C zlib

cipher.o: cipher.h
ciphervar.o: ciphervar.h
error.o: error.h
zlf.o: zlf.h
options.o: options.h
sha1.o: sha1.h
sys_linux.o: sys_linux.h
twofish.o: twofish.h
aes.o: aes.h
blowfish.o: blowfish.h
cast.o: cast.h
serpent.o: serpent.h
tripledes.o: tripledes.h
var.o: var.h
bzf.o: bzip2/bzlib.h
#rm_opts.o: rm_opts.h

status-make-bzlib:
	@echo "--makeing libbz2"
status-make-bzlib-done:
	@echo "--makeing libbz2 done"
status-make-cpdu:
	@echo "--makeing cpdu" $(VERSION)
status-make-cpdu-done:
	@echo "--makeing cpdu" $(VERSION) "done"
status-make-zlib:
	@echo "--makeing zlib 1.2.3"
status-make-zlib-done:
	@echo "--makeing zlib 1.2.3 done"
#status-make-rm:
#	@echo "--makeing system remove replacement"
#status-make-rm-done:
#	@echo "--makeing system remove replacement done"

strip:
	strip ./cpdu

distclean: clean zlib-clean
zlib-clean:
	make -C zlib clean
clean:
	rm ./cpdu *.o -f
install:
	cp cpdu /usr/local/bin
#install-man:
#	cp cpdu.1 /usr/local/share/man/man1
