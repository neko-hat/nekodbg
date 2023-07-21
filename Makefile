all: nekodbg

nekodbg: linenoise.o main.o
	gcc -o nekodbg linenoise.o main.o -l elf

linenoise.o: linenoise.h linenoise.c
	gcc -c -o linenoise.o linenoise.c

main.o: main.c linenoise.h
	gcc -c -o main.o main.c 

clean:
	rm -f *.o
	rm -f nekodbg