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
	
	while(true){
		q->_servMutex->lock();
		if(q->_answers.size() > 0){
		
			cout << "ANSWERS " << endl;
			for(auto iter = q->_answers.begin(); iter < q->_answers.end(); iter++){
				cout << *iter << endl;
			}
			q->_ansMutex->unlock();
			break;
		}
		q->_servMutex->unlock();
		
	
	
	}
	return 0;


}
