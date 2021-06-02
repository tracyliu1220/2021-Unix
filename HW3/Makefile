
all: libmini.so

libmini64.o: libmini64.asm
	yasm -f elf64 -DYASM -D__x86_64__ -DPIC libmini64.asm -o libmini64.o

libmini.o: libmini.c
	gcc -c -g -Wall -fno-stack-protector -fPIC -nostdlib libmini.c

libmini.so: libmini64.o libmini.o
	ld -shared -o libmini.so libmini64.o libmini.o

start.o: start.asm
	yasm -f elf64 -DYASM -D__x86_64__ -DPIC start.asm -o start.o

test.o: test.c
	gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI test.c

test: test.o start.o libmini.so
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o test test.o start.o -L. -L.. -lmini

.PHONY: all clean testing

clean:
	rm -f *.o *.so test

testing: test
	LD_LIBRARY_PATH=. ./test test.c
