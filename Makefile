all: binflow
binflow: main.o elf.o maps.o trace.o util.o disas.o 
	gcc -g main.o elf.o maps.o trace.o util.o disas.o capstone-2.1.2/libcapstone.a -o binflow
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
clean:
	rm -f *.o binflow

