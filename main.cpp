#include "resolver.h"
#include <string>
#include <utility>
#include <list>
#include <ostream>
#include <iostream>
#include "network.h"
#include <memory>

using namespace std;

const string domainCommand = "-d";
const string queryTypeCommand = "-t";
const string helpCommand = "-h";

int main(int argc, char** argv){

	if(argc < 2){
		cout << "Resolver needs at least one argument. Use ./resolver -h for more information." << endl;
		return -1;
	
	}
	
	
	loadSafeties("/home/kali/DNS-resolver/sbelt.txt");

	
	shared_ptr<QueryState> q = make_shared<QueryState>(argv[1], (uint16_t)ResourceTypes::a,  (uint16_t)ResourceClasses::in);
	QueryState::solveStandardQuery(q);
	
	
	
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
	
	dumpCacheToFile();
		
	return 0;


}
