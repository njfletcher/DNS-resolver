#include "resolver.h"
#include <string>
#include <utility>
#include <list>
#include <ostream>
#include <iostream>
#include "network.h"

using namespace std;

int main(int argc, char** argv){

	if(argc < 2){
		cout << "Provide a safety belt file" << endl;
		return -1;
	
	}

	string fileP(argv[1]);
	list<pair<string,string>>* sPtr = readSafetyFile(fileP);
	
	if(sPtr == NULL){
		cout << "invalid list" << endl;
		return -1;
	
	}
	else{
	
		list<pair<string,string>> servers = *sPtr;
		for(auto iter = servers.begin(); iter != servers.end(); iter++){
		
			pair<string,string> server = *iter;
			cout << server.first << " " << server.second << endl;
			sendMessageResolverClient(server.first);
		}
	
	}
	
	return 0;


}
