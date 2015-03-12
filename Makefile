all: binflow
binflow: main.o elf.o maps.o trace.o util.o disas.o antidebug.o
	gcc -g main.o elf.o maps.o trace.o util.o disas.o antidebug.o capstone/libcapstone.a -o binflow
main.o:
	gcc -g -c main.c
elf.o:
	gcc -g -c elf.c
maps.o:
	gcc -g -c maps.c
trace.o:
	gcc -g -c trace.c
util.o:
	gcc -g -c util.c
disas.o:
	gcc -g -c disas.c
antidebug.o:
	gcc -g -c antidebug.c
clean:
	rm -f *.o binflow

