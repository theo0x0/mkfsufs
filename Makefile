DESTDIR = ""

compile:
	gcc -Wall -o mkfs.ufs src/mkfsufs.c

install:
	mkdir -p $(DESTDIR)/usr/bin
	cp ./mkfs.ufs $(DESTDIR)/usr/bin
