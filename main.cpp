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

	
	QueryState* q = new QueryState(argv[1], (uint16_t)ResourceTypes::a,  (uint16_t)ResourceClasses::in);
	solveStandardQuery(q);
	
	return 0;


}
