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



shared_ptr<DNSMessage> sendStandardQuery(string nameServerIp, string questionDomainName, uint16_t id){

	DNSFlags flg((uint8_t)qrVals::query, (uint8_t) opcodes::standard, 0, 0, 0, 0, 0, 0);
	DNSHeader hdr(id, flg, 1, 0, 0,0);
	QuestionRecord q(questionDomainName.c_str(), (uint16_t)ResourceTypes::a, (uint16_t)ResourceClasses::in);
	vector<QuestionRecord> qr = {q};
	vector<ResourceRecord> rr;
	DNSMessage msg(hdr, qr, rr, rr, rr );
	vector<uint8_t> buff;
	vector<uint8_t> resp;
	msg.toBuffer(buff);
	msg.print();
	sendMessageResolverClient(nameServerIp, buff, resp);
	auto iter = resp.begin();
	return make_shared<DNSMessage>(iter, iter, resp.end());

}
