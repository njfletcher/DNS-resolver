#include "resolver.h"
#include <string>
#include <utility>
#include <list>
#include <ostream>
#include <iostream>
#include "network.h"
#include <memory>

using namespace std;

#define argCount 3

int main(int argc, char** argv){

	if(argc < argCount){
		cout << "provide a domain name and safety file" << endl;
		return -1;
	
	}
	
	vector<pair<string,string> > servers;
	readSafetyFile(argv[2], servers);

	verifyRootNameServers(servers);
	
	return 0;


}
