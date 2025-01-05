resolver: main.o structures.o resolver.o network.o
	g++ -o resolver main.o resolver.o structures.o network.o -g 
main.o: main.cpp
	g++ -c main.cpp -g
structures.o: structures.cpp structures.h
	g++ -c structures.cpp -g
resolver.o: resolver.cpp resolver.h
	g++ -c resolver.cpp -g
network.o: network.cpp network.h
	g++ -c network.cpp -g
clean:
	rm *.o resolver
