#include "resolver.h"
#include <iostream>
#include <fstream>
#include <string>
#include <utility>
#include <ostream>
#include <memory>
#include "structures.h"
#include <vector>
#include "network.h"
#include <arpa/inet.h>
using namespace std;

//expects a file path, with each line of that file being a root entry. Format of each line is ip;domain name
void readSafetyFile(string filePath, vector<pair<string,string> >& servers){

	string currLine;
	size_t delimPos;
	unsigned int numServers = 0;
	
	ifstream inp(filePath);
	
	while(getline(inp,currLine)){
		
		numServers++;
		delimPos = currLine.find(";");
		
		if(delimPos == string::npos){
			cout << "Invalid safety belt file format: line is missing semi colon" << endl;
		
		}
		else{
			
			string ipAddress = currLine.substr(0,delimPos);
			string domainName = currLine.substr(delimPos+1);
			pair<string,string> pr(ipAddress, domainName);
			servers.push_back(pr);
		
		}

	
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

string convertIpIntToString(uint32_t ip){

	char buffer[INET_ADDRSTRLEN];
	struct in_addr a;
	a.s_addr = ip;
	
	inet_ntop(AF_INET, &a, buffer, INET_ADDRSTRLEN);
	
	string s = string(buffer);
	
	return s;

}

int continueQuery(DNSMessage & resp, vector<string>& answerIps, vector<pair <string, string> >& authMaps, vector<pair <string, string> >& additMaps){

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
				if(ip > 0) answerIps.push_back(convertIpIntToString(ip));
			
			}
		
		}
		if(answerIps.size() > 0) return (int) SessionStates::answered;
	
	}
	
	uint16_t numAuthClaim = resp._hdr._numAuthRR;
	size_t numAuthActual = resp._authority.size();
	if(numAuthClaim > 0){
		
		for(size_t i =0; i < numAuthActual; i++){
			ResourceRecord r = resp._authority[i];
			if( r._rType == (uint8_t)ResourceTypes::ns){
				string domain = ResourceRecord::getNSData(msgBuff, r._rData);
				pair<string, string> p(domain,"");
				authMaps.push_back(p);
			}
		
		}
	
	}
	
	uint16_t numAdditClaim = resp._hdr._numAdditRR;
	size_t numAdditActual = resp._additional.size();
	if(numAdditClaim > 0){
		
		for(size_t i =0; i < numAdditActual; i++){
			ResourceRecord r = resp._additional[i];
			if( r._rType == (uint8_t)ResourceTypes::a){
			
				string name = convertOctetSeqToString(r._name);
				uint32_t ip = ResourceRecord::getInternetData(r._rData);
				bool matched = false;
				for(auto iter = authMaps.begin(); iter != authMaps.end(); iter++){
					pair<string, string>& p = *iter;
					if(p.first == name){
						p.second = convertIpIntToString(ip);
						matched = true;
						break;
					}
				
				}
				if(!matched){
					pair<string, string > p(name,convertIpIntToString(ip));
					additMaps.push_back(p);
				}
			}
		
		}
		
		return (int) SessionStates::continued;
	
	}
	
	
	
	return (int) SessionStates::failed;

} 

int solveStandardQuery(string nameServerIp, string questionDomainName, uint16_t id, vector<string>& answers, bool recursive, vector<pair<string,string> >& safety){

	
	cout << "SOLVING NAMESERVER: " << nameServerIp << " QUESTION: " << questionDomainName << endl;
	
	shared_ptr<DNSMessage> respPtr = sendStandardQuery(nameServerIp,questionDomainName, id);
	DNSMessage resp = *respPtr;
	resp.print();
	
	vector<pair<string,string> > auths;
	vector<pair<string,string> > addits;

	int ret = continueQuery(resp,answers,auths,addits);
		
	if(ret == (int) SessionStates::answered){
	
		cout << "FINAL ANSWERS" << endl;
		for(auto iter = answers.begin(); iter != answers.end(); iter++){
			cout << "ip " << *iter << " " << endl;
		
		}
		return (int) SessionStates::answered;
		
	}
	else if (ret == (int) SessionStates::continued){
	
		cout << "AUTH CONTINUED" << endl;
		for(auto authIter = auths.begin(); authIter != auths.end(); authIter++){
		
			pair<string,string> authP = *authIter;
			string authIp = authP.second;
			string authName = authP.first;
			cout << "domain " << authName << " ip " << authIp << endl;
				
			/*if(p.second != "" && recursive){
				int ret = solveStandardQuery(p.second,questionDomainName,id,answers);
				if(ret == (int) SessionStates::answered){
					return (int) SessionStates::answered;
				}
				
			}
			*/
			bool answerFound = false;
			for(auto safetyIter = safety.begin(); safetyIter != safety.end() && !answerFound; safetyIter++){
				
				pair<string,string> sP = *safetyIter;
				string sIp = sP.second;
				string sName = sP.first;
				
				if(sName != authName){
					vector<string> ips;
					solveStandardQuery(sIp,authName,id,ips,recursive,safety);
						
					for(auto conIter = ips.begin(); conIter != ips.end() && !answerFound; conIter++){
					
						int contRet = solveStandardQuery(*conIter, questionDomainName,id,answers,recursive,safety);
						if(contRet == (int) SessionStates::answered) answerFound = true;
					}
				}
				
				
				
			}
			if(answerFound){
				return (int) SessionStates::answered;
			}
			else return (int) SessionStates::failed;
				
				
		
		}
		
		cout << "ADDIT CONTINUED" << endl;
		for(auto iter = addits.begin(); iter != addits.end(); iter++){
		
			pair<string,string> p = *iter;
			cout << "domain " << p.first << " ip " << p.second << endl;
		
		}
	
	}

	
	return (int) SessionStates::failed;


}


void verifyRootNameServers(vector<pair<string,string> >& servers){

	
	for(auto iter = servers.begin(); iter != servers.end(); iter++){
	
		
		pair<string,string> questionServer = *iter;
		string questionIp = questionServer.second;
		string questionName = questionServer.first;
		
		cout << "VERIFYING SERVER: " << questionName << " HAS IP: " << questionIp << endl;
		
		for(auto innerIter = servers.begin(); innerIter != servers.end(); innerIter++){
		
			pair<string,string> server = *innerIter;
			string serverIp = server.second;
			string serverName = server.first;
			
			cout << "CONSULTING SERVER: " << serverName << endl;
			
			if(serverName != questionName){
			
				vector<string> ips;
				vector<pair<string,string> > safe = {server};
				solveStandardQuery(serverIp, questionName, 0, ips, true, safe);
				
				for(auto aIter = ips.begin(); aIter != ips.end(); aIter++){
					string ansIp = *aIter;
					cout << ansIp << endl;
					if(ansIp == questionIp) cout << "IP VERIFIED" << endl;					
					
				
				}
			
			}
		
		}
		
	}



}

