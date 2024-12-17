resolver: main.o structures.o resolver.o network.o
	g++ -o resolver main.o resolver.o structures.o network.o -lc
main.o: main.cpp
	g++ -g -c main.cpp -lc
structures.o: structures.cpp structures.h
	g++ -g -c structures.cpp -lc
resolver.o: resolver.cpp resolver.h
	g++ -g -c resolver.cpp -lc
network.o: network.cpp network.h
	g++ -g -c network.cpp -lc
clean:
	rm *.o resolver
