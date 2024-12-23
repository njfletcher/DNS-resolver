resolver: main.o structures.o resolver.o network.o
	g++ -o resolver main.o resolver.o structures.o network.o -fsanitize=address -static-libasan -g 
main.o: main.cpp
	g++ -c main.cpp -fsanitize=address -static-libasan -g
structures.o: structures.cpp structures.h
	g++ -c structures.cpp -fsanitize=address -static-libasan -g
resolver.o: resolver.cpp resolver.h
	g++ -c resolver.cpp -fsanitize=address -static-libasan -g
network.o: network.cpp network.h
	g++ -c network.cpp -fsanitize=address -static-libasan -g
clean:
	rm *.o resolver
