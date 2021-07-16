all: pcapTest

pcapTest: utils.o main.o
		gcc -g -o pcapTest utils.o main.o -lpcap

main.o: pcapTest.h main.c

utils.o: pcapTest.h utils.c

clean:
		rm -f pcapTest
		rm -f *.o