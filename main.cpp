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
	


	
	shared_ptr<DNSMessage> respPtr = sendStandardQuery("128.252.0.100",argv[1], 1);
	DNSMessage resp = *respPtr;
	resp.print();
	
	vector<uint32_t> ips;
	vector<string> nms;
	int ret = continueQuery(resp,ips,nms);
	if(ret == (int) SessionStates::answered){
		printf("ip: %i", ips[0]);
		
	}
	else if (ret == (int) SessionStates::continued){
	
		for(auto iter = nms.begin(); iter != nms.end(); iter++){
			cout << *iter << " " << endl;
		
		}
	
	}
	
	
	
	return 0;


}
