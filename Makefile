DESTDIR = ""

compile:
	gcc -Wall -o mkfs.ufs src/mkfsufs.c

install:
	cp ./mkfs.ufs $(DESTDIR)/usr/bin
