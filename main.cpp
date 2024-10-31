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
	

	string fileP(argv[2]);
	shared_ptr< list<pair<string,string>> > sPtr = readSafetyFile(fileP);
	
	/*if(sPtr == NULL){
		cout << "invalid list" << endl;
		return -1;
	
	}
	else{
	
		list<pair<string,string>> servers = *sPtr;
		for(auto iter = servers.begin(); iter != servers.end(); iter++){
		
			pair<string,string> server = *iter;
			cout << server.first << " " << server.second << endl;
			sendMessageResolverClient(server.first);
		}
	
	}
	*/
	shared_ptr<DNSMessage> respPtr = sendStandardQuery("128.252.0.100",argv[1], 1);
	DNSMessage resp = *respPtr;
	continueQuery(resp);
	
	resp.print();
	printf("ip: %i", ResourceRecord::getIpAddressFromAAnswer(resp._answer[0]));

	
	return 0;


}
