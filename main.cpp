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
	
	
	loadSafeties(argv[2]);

	
	shared_ptr<QueryState> q = make_shared<QueryState>(argv[1], (uint16_t)ResourceTypes::a,  (uint16_t)ResourceClasses::in);
	q->solveStandardQuery();
	
	dumpCacheToFile();
	
	q->displayResult();
	
	return 0;


}
