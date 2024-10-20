#include "resolver.h"
#include <iostream>
#include <fstream>
#include <string>
#include <utility>
#include <list>
#include <ostream>
#include <memory>
#include "structures.h"
#include <vector>
#include "network.h"
using namespace std;

//expects a file path, with each line of that file being a root entry. Format of each line is ip;domain name
shared_ptr< list<pair<string,string>> > readSafetyFile(string filePath){

	string currLine;
	size_t delimPos;
	unsigned int numServers = 0;
	shared_ptr< list<pair<string,string>> > lPtr = make_shared< list<pair<string,string>> >();
	
	ifstream inp(filePath);
	
	while(getline(inp,currLine)){
		
		numServers++;
		delimPos = currLine.find(";");
		
		if(delimPos == string::npos){
			cout << "Invalid safety belt file format: line is missing semi colon" << endl;
			return NULL;
		
		}
		else{
			
			string ipAddress = currLine.substr(0,delimPos);
			string domainName = currLine.substr(delimPos+1);
			pair<string,string> pr(ipAddress, domainName);
			lPtr->push_back(pr);
		
		}

	
	}
	
	if(numServers == 0){
		cout << "Invalid safety belt file format: file must have at least one server" << endl;
		return NULL;
	}
	else{
	
		return lPtr;
	}


}


void sendTestQuery(){

	DNSFlags flg(qrVals::query, opcodes::standard, 0, 0, 0, 0, 0, 0);
	DNSHeader hdr(5, &flg, 1, 0, 0,0);
	string s = "google.com";
	QuestionRecord q(s.c_str(), ResourceTypes::a, ResourceClasses::in);
	DNSMessage msg(&hdr, &q, NULL, NULL, NULL );
	vector<uint8_t> v;
	msg.toBuffer(v);
	sendMessageResolverClient(string("128.252.0.100"), v);
	
	
}
