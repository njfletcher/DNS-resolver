resolver: main.o structures.o resolver.o network.o
	g++ -o resolver main.o resolver.o structures.o network.o
main.o: main.cpp
	g++ -c main.cpp
structures.o: structures.cpp structures.h
	g++ -c structures.cpp
resolver.o: resolver.cpp resolver.h
	g++ -c resolver.cpp
network.o: network.cpp network.h
	g++ -c network.cpp
clean:
	rm *.o resolver
