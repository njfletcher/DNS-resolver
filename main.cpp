#include "resolver.h"
#include <string>
#include <utility>
#include <list>
#include <ostream>
#include <iostream>

using namespace std;

int main(int argc, char** argv){

	string fileP(argv[1]);
	list<pair<string*,string*>*>* sPtr = readSafetyFile(fileP);
	
	if(sPtr == NULL){
		cout << "invalid list" << endl;
		return -1;
	
	}
	else{
	
		list<pair<string*,string*>*> servers = *sPtr;
		for(auto iter = servers.begin(); iter != servers.end(); iter++){
		
			pair<string*,string*>* server = *iter;
			cout << *(server->first) << " " << *(server->second) << endl;
		}
	
	}
	
	return 0;


}
