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
	
	string startIp = "";
	for(auto iter = servers.begin(); iter < servers.end(); iter++){
		pair<string,string> p = *iter;
		if(p.first != ""){
			startIp = p.first;
			break;
		}
	
	}
	
	vector<string> ans;
	if(startIp != ""){
		solveStandardQuery(startIp, argv[1], 0, ans, true, servers);
		cout << "ANSWERS+++++++++++++++++++++++++++++++++++++++++++++++=" << endl;
		for(auto iter = ans.begin(); iter < ans.end(); iter++){
			cout << *iter <<endl;
		
		}
	}
	else{
		cout << "no valid start points for query" << endl;
	}
	
	
	return 0;


}
