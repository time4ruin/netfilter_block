all : netfilter_block

netfilter_block: main.o
	g++ -o netfilter_block main.o -lnetfilter_queue

main.o:
	g++ -c -o main.o main.cpp

clean:
	rm -f netfilter_block
	rm -f *.o

