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
	


	vector<string> ips;
	solveStandardQuery("128.252.0.100",argv[1], 1,ips);
	
	
	return 0;


}
