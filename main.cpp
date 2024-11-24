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
	
	/*vector<pair<string,string> > servers;
	readSafetyFile(argv[2], servers);

	verifyRootNameServers(servers);
	
	string startIp = "";
	for(auto iter = servers.begin(); iter < servers.end(); iter++){
		pair<string,string> p = *iter;
		if(p.first != ""){
			startIp = p.first;
			break;
		}
	
	}
	
	*/
	
	QueryState q = QueryState(argv[1], (uint16_t)ResourceTypes::a,  (uint16_t)ResourceClasses::in);
	solveStandardQuery(q);
	
	
	return 0;


}
