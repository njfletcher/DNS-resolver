resolver: main.o structures.o resolver.o network.o
	g++ -o resolver main.o resolver.o structures.o network.o
main.o: main.cpp
	g++ -g -c main.cpp
structures.o: structures.cpp structures.h
	g++ -g -c structures.cpp
resolver.o: resolver.cpp resolver.h
	g++ -g -c resolver.cpp
network.o: network.cpp network.h
	g++ -g -c network.cpp
clean:
	rm *.o resolver
