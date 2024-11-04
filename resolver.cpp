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

int continueQuery(DNSMessage & resp, vector<uint32_t>& ips, vector<string>& domainNames){

	vector<uint8_t> msgBuff;
	resp.toBuffer(msgBuff);
	if(resp._hdr._flags._qr != (uint8_t) qrVals::response){
		return (int) SessionStates::failed;
	
	}
	
	if(resp._hdr._flags._rcode != (uint8_t) ResponseCodes::none){
		return (int) SessionStates::failed;
	
	}
	
	uint16_t numAnswersClaim = resp._hdr._numAnswers;
	size_t numAnswersActual = resp._answer.size();
	if(numAnswersClaim > 0){
		
		for(size_t i =0; i < numAnswersActual; i++){
			ResourceRecord r = resp._answer[i];
			if( r._rType == (uint8_t)ResourceTypes::a){
			
				uint32_t ip = ResourceRecord::getInternetData(r._rData);
				if(ip > 0) ips.push_back(ip);
			
			}
		
		}
		if(ips.size() > 0) return (int) SessionStates::answered;
	
	}
	
	uint16_t numAuthClaim = resp._hdr._numAuthRR;
	size_t numAuthActual = resp._authority.size();
	if(numAuthClaim > 0){
		
		for(size_t i =0; i < numAuthActual; i++){
			ResourceRecord r = resp._authority[i];
			if( r._rType == (uint8_t)ResourceTypes::ns){
				domainNames.push_back(ResourceRecord::getNSData(msgBuff, r._rData));
			
			}
		
		}
		
		return (int) SessionStates::continued;
	
	}
	else return (int) SessionStates::failed;
	

} 


