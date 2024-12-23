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
	QueryState::solveStandardQuery(q);
	
	//dumpCacheToFile();
	
	q->displayResult();
	
	
	moreThreads.store(false);
	
	while(true){
	
		threadMutex.lock();
		if(threads.size() < 1){
			threadMutex.unlock();
			break;
		}
		else{
			thread& t = threads.back();
			if(t.joinable()){
				threadMutex.unlock();
				t.join();
			}
			else{
				threadMutex.unlock();
				threads.pop_back();
			
			}
			
		
		}
	

	}
		
	return 0;


}
