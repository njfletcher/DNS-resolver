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
	
	vector<string> ips;
	vector<pair<string,string> > auths;
	vector<pair<string,string> > addits;
	int ret = continueQuery(resp,ips,auths,addits);
	
	if(ret == (int) SessionStates::answered){
	
		cout << "FINAL ANSWERS" << endl;
		for(auto iter = ips.begin(); iter != ips.end(); iter++){
			cout << "ip " << *iter << " " << endl;
		
		}
		
	}
	else if (ret == (int) SessionStates::continued){
	
		cout << "AUTH CONTINUED" << endl;
		for(auto iter = auths.begin(); iter != auths.end(); iter++){
		
			pair<string,string> p = *iter;
			cout << "domain " << p.first << " ip " << p.second << endl;
		
		}
		
		cout << "ADDIT CONTINUED" << endl;
		for(auto iter = addits.begin(); iter != addits.end(); iter++){
		
			pair<string,string> p = *iter;
			cout << "domain " << p.first << " ip " << p.second << endl;
		
		}
	
	}
	
	
	return 0;


}
