# keep these in-sync with the #defines in crash_handler.c
VERSION=0
REVISION=7

PROG = crash_handler
INCDIRS = -I/usr/local/include -I/usr/include
LIBDIRS = -L/usr/local/lib -L/usr/lib
LIBS = -lunwind-x86_64 -lunwind-ptrace
LDFLAGS =

OBJECTS = crash_handler.o \
	utility.o \
	journal.o

$(PROG): $(OBJECTS)
	$(CROSS_COMPILE)gcc $^ -o $@ ${LDFLAGS} ${INCDIRS} ${LIBDIRS} ${LIBS}

%.o: %.c
	$(CROSS_COMPILE)gcc -c $< -o $@ ${LDFLAGS} ${INCDIRS} ${LIBDIRS} ${LIBS}

clean:
	rm -f $(PROG) $(OBJECTS)

distclean:
	-make clean
	-make -C test clean

default_install:
	# this won't work unless you are self-hosted on ARM
	cp $(PROG) /tmp
	/tmp/$(PROG) --install

install: default_install

distribution:
	-make distclean
	cd .. ; ln -s crash_handler crash_handler-${VERSION}.${REVISION} ; \
	tar -czvf crash_handler-${VERSION}.${REVISION}.tgz crash_handler-${VERSION}.${REVISION}/* ; \
	unlink crash_handler-${VERSION}.${REVISION}

help:
	@echo "Here are some supported targets for this Makefile:"
	@echo
	@echo "  install:      install the crash_handler program"
	@echo "  clean:        remove generated files"
	@echo "  distclean:    remove generated files, including in subdirs"
	@echo "  distribution: create a distribution tarball"
