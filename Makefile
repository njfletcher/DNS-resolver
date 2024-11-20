resolver: main.o structures.o resolver.o network.o
	gcc -o resolver main.o structures.o resolver.o network.o
main.o: main.cpp
	gcc -c main.cpp
structures.o: structures.cpp
	gcc -c structures.cpp
resolver.o: resolver.cpp
	gcc -c resolver.cpp
network.o: network.cpp
	gcc -c network.cpp
