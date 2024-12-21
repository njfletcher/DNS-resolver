resolver: main.o structures.o resolver.o network.o
	g++ -o resolver main.o resolver.o structures.o network.o -fsanitize=address -static-libasan 
main.o: main.cpp
	g++ -g -c main.cpp -fsanitize=address -static-libasan
structures.o: structures.cpp structures.h
	g++ -g -c structures.cpp -fsanitize=address -static-libasan
resolver.o: resolver.cpp resolver.h
	g++ -g -c resolver.cpp -fsanitize=address -static-libasan
network.o: network.cpp network.h
	g++ -g -c network.cpp -fsanitize=address -static-libasan
clean:
	rm *.o resolver
