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

vector<uint16_t> takenIds;
vector<pair<string,string> > safety;


QueryState::QueryState(uint16_t id, std::string sname, uint16_t stype, uint16_t sclass, int networkCode): _id(id), _sname(sname), _stype(stype), _sclass(sclass), _networkCode(networkCode) {};
NameServerInfo::NameServerInfo(string name, string address, int score): _name(name), _address(address), _score(score) {};
SList::SList(): _matchCount(0) {};

//expects a file path, with each line of that file being a root entry. Format of each line is ip;domain name
void loadSafeties(string filePath){

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
			safety.push_back(pr);
		
		}

	
	}
	
}

string convertIpIntToString(uint32_t ip){

	char buffer[INET_ADDRSTRLEN];
	struct in_addr a;
	a.s_addr = ip;
	
	inet_ntop(AF_INET, &a, buffer, INET_ADDRSTRLEN);
	
	string s = string(buffer);
	
	return s;

}

uint16_t pickNextId(){
	
	uint16_t max = 0;
	for(auto iter = takenIds.begin(); iter < takenIds.end(); iter++){
		if(*iter > max) max = *iter;
	
	}
	return max + 1;

}

void reclaimId(uint16_t id){
	
	auto iter = takenIds.begin();
	bool found = false
	for(; iter < takenIds.end(); iter++){
		if(*iter == id){
			found = true;
			break;
		{
	
	}
	
	if(found){
		takenIds.erase(iter);
	}

}



shared_ptr<QueryState> sendStandardQuery(string nameServerIp, string questionDomainName){

	uint16_t id = pickNextId();
	
	DNSFlags flg((uint8_t)qrVals::query, (uint8_t) opcodes::standard, 0, 0, 0, 0, 0, 0);
	DNSHeader hdr(id, flg, 1, 0, 0,0);
	QuestionRecord q(questionDomainName.c_str(), (uint16_t)ResourceTypes::a, (uint16_t)ResourceClasses::in);
	
	vector<QuestionRecord> qr = {q};
	vector<ResourceRecord> rr;
	DNSMessage msg(hdr, qr, rr, rr, rr );
	
	vector<uint8_t> buff;
	vector<uint8_t> resp;
	msg.toBuffer(buff);

	int networkResult = sendMessageResolverClient(nameServerIp, buff, resp);
	shared_ptr<QueryState> state = make_shared<QueryState>(id, questionDomainName, (uint16_t)ResourceTypes::a,  (uint16_t)ResourceClasses::in, networkResult);
	
	if(networkResult == (int) NetworkCodes::none){
		auto iter = resp.begin();
		state->_lastResponse = make_shared<DNSMessage>(iter, iter, resp.end());
	
	}
	else{
		//no point in using this id further, just need to make sure calling code doesnt try to send more network requests with this id(unless it gets chosen again).
		reclaimId(id);
	}
	
	return state;

}


bool QueryState::checkForResponseErrors(){

	DNSMessage resp = *(_lastResponse);

	if(_networkCode != (int) NetworkErrors::none){
	
		return true;
	}


	if(resp._hdr._flags._qr != (uint8_t) qrVals::response){
	
		return true;
	
	}
	
	uint8_t respCode = resp._hdr._flags._rcode;
	if(respCode != (uint8_t) ResponseCodes::none){
	
		return true;
	
	}
	
	if(_id != resp._hdr._transId){
	
		return true;
	
	}

	return false;

}




int QueryState::extractDataFromResponse(){


	if(checkForResponseErrors()) return (int) SessionStates::failed;
	
	
	vector<uint8_t> msgBuff;
	_lastResponse.toBuffer(msgBuff);
	
	uint16_t numAnswersClaim = resp._hdr._numAnswers;
	size_t numAnswersActual = resp._answer.size();
	//dont need to bother checking if they dont claim there are any answers. But dont trust the claimed number for looping, could be huge or at least incorrect.
	if(numAnswersClaim > 0){
		
		for(size_t i =0; i < numAnswersActual; i++){
			ResourceRecord r = resp._answer[i];
			if( r._rType == (uint8_t)ResourceTypes::a){
			
				uint32_t ip = ResourceRecord::getInternetData(r._rData);
				if(ip > 0) answerIps.push_back(convertIpIntToString(ip));
			
			}
		
		}
		if(answerIps.size() > 0) return SessionStates::answered;
	
	}
	
	uint16_t numAuthClaim = resp._hdr._numAuthRR;
	size_t numAuthActual = resp._authority.size();
	if(numAuthClaim > 0){
		
		for(size_t i =0; i < numAuthActual; i++){
			ResourceRecord r = resp._authority[i];
			if( r._rType == (uint8_t)ResourceTypes::ns){
				string domain = ResourceRecord::getNSData(msgBuff, r._rData);
				pair<string, string> p("",domain);
				authMaps.push_back(p);
			}
		
		}
	
	}
	
	uint16_t numAdditClaim = resp._hdr._numAdditRR;
	size_t numAdditActual = resp._additional.size();
	if(numAdditClaim > 0){
		
		//matching recieved a records in addit to domain names in auth section. this should be handled by cache later.
		for(size_t i =0; i < numAdditActual; i++){
			ResourceRecord r = resp._additional[i];
			if( r._rType == (uint8_t)ResourceTypes::a){
			
				string name = convertOctetSeqToString(r._name);
				uint32_t ip = ResourceRecord::getInternetData(r._rData);
				bool matched = false;
				for(auto iter = authMaps.begin(); iter != authMaps.end(); iter++){
					pair<string, string>& p = *iter;
					if(p.second == name){
						p.first = convertIpIntToString(ip);
						matched = true;
						break;
					}
				
				}
				if(!matched){
					pair<string, string > p(convertIpIntToString(ip), name);
					additMaps.push_back(p);
				}
			}
		
		}
		
		return SessionStates::continued;
	
	}
	
	
	
	return SessionStates::failed;

} 



shared_ptr<QueryState> solveSubQuery(string leadName){

	bool answerFound = false;
	for(auto safetyIter = safety.begin(); safetyIter != safety.end() && !answerFound; safetyIter++){
				
		pair<string,string> sP = *safetyIter;
		string sIp = sP.first;
		string sName = sP.second;
				
		if(sName != authName){
			vector<string> ips;
			solveStandardQuery(sIp,authName,id,ips,recursive,safety);
			for(auto conIter = ips.begin(); conIter != ips.end() && !answerFound; conIter++){
				int contRet = solveStandardQuery(*conIter, questionDomainName, answers,recursive,safety);
				if(contRet == SessionStates::answered) answerFound = true;
			}
		}
				
				
				
	}

}

shared_ptr<QueryState> solveStandardQuery(string nameServerIp, string questionDomainName){

	
	cout << "SOLVING NAMESERVER: " << nameServerIp << " QUESTION: " << questionDomainName << endl;
	
	shared_ptr<QueryState> queryState = sendStandardQuery(nameServerIp,questionDomainName);
	SessionStates initialReturn = queryState.extractDataFromResponse();
		
	if(initialReturn == SessionStates::answered){
	
		return queryState;
		
		
	}
	//we didnt get an answer, but we should investigate the authoritative servers that might allow us to continue
	else if (initialReturn == SessionStates::continued){
	
		vector<struct NameServerInfo> leads = _servs._servers;
	
		for(auto leadIter = leads.begin(); leadsIter != leads.end(); leadIter++){
		
			pair<string,string> leadP = *leadIter;
			string leadIp = leadP.first;
			string leadName = leadP.second;
			cout << "domain " << authName << " ip " << authIp << endl;
				
			if(leadIp != ""){
				shared_ptr<QueryState> leadState = solveStandardQuery(leadIp,questionDomainName);
				
			}
			else{
			
			
			}
			
			
			if(answerFound){
				return SessionStates::answered;
			}
			else return SessionStates::failed;
				
				
		
		}
		
		cout << "ADDIT CONTINUED" << endl;
		for(auto iter = addits.begin(); iter != addits.end(); iter++){
		
			pair<string,string> p = *iter;
			cout << "domain " << p.second << " ip " << p.first << endl;
		
		}
	
	}
	else{
		return SessionStates::failed;
	
	}
	
	return SessionStates::failed;


}


void verifyRootNameServers(vector<pair<string,string> >& servers){

	
	for(auto iter = servers.begin(); iter != servers.end(); iter++){
	
		
		pair<string,string> questionServer = *iter;
		string questionIp = questionServer.first;
		string questionName = questionServer.second;
		
		cout << "VERIFYING SERVER: " << questionName << " HAS IP: " << questionIp << endl;
		
		bool verified = false;
		for(auto innerIter = servers.begin(); innerIter != servers.end() && !verified; innerIter++){
		
			pair<string,string> server = *innerIter;
			string serverIp = server.first;
			string serverName = server.second;
			
			if(serverName != questionName){
			
				cout << "CONSULTING SERVER: " << serverName << endl;
			
				vector<string> ips;
				vector<pair<string,string> > safe = {server};
				solveStandardQuery(serverIp, questionName, 0, ips, true, safe);
				
				for(auto aIter = ips.begin(); aIter != ips.end() && !verified; aIter++){
					string ansIp = *aIter;
					cout << ansIp << endl;
					if(ansIp == questionIp){
						cout << "IP VERIFIED" << endl;
						verified = true;
					}					
					
				
				}
			
			}
		
		}
		if(!verified){
			cout << "root server ip not verified, consider updating it." << endl;
		
		}
		
	}



}

