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
#include <unordered_map>
#include <unistd.h> 
#include <list>

using namespace std;

vector<uint16_t> takenIds;
vector<pair<string,string> > safety;
//maps domain name to valid resource records
unordered_map<string, list<ResourceRecord> > cache;

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

QueryState::~QueryState(){

	reclaimId(_id);

}

QueryState::QueryState(std::string sname, uint16_t stype, uint16_t sclass): _id(id), _sname(sname), _stype(stype), _sclass(sclass), _networkCode(NetworkErrors::none) {

	_startTime = time(NULL);
	_id = pickNextId();
}

QueryState::QueryState(std::string sname, uint16_t stype, uint16_t sclass, shared_ptr<int> globalOps): _id(id), _sname(sname), _stype(stype), _sclass(sclass), _networkCode(NetworkErrors::none) {

	_numOpsGlobal = globalOps;
	_startTime = time(NULL);
	_id = pickNextId();
}


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



void insertRecordIntoCache(ResourceRecord& r){

	//if a ttl of 0, shouldnt cache it globally. This record will be cached locally for the query in the DNSMessage itself.
	if(r._ttl > 0){
		list<ResourceRecord>& records = cache[convertOctetSeqToString(r._name)];
		records.push_back(r);
	}

}

list<ResourceRecord> getRecordsFromCache(string domainName){

	
	if(cach.find(domainName) != cache.end()){
		list<ResourceRecord>& records = cache[convertOctetSeqToString(r._name)];
		for(auto iter = records.begin(); iter < records.end(); iter++){
			ResourceRecord r = *iter;
			if(r._cacheExpireTime < time(NULL)){
				records.erase(iter);
			}
		
		}
		
		return records;
	
	}
	else{
		return list<ResourceRecord>();
	}

}


//assumes errors have been checked for in the response(Dont want to cache any records that come from a bad response).
QueryState::cacheRecords(){

	for(auto iter = _lastResponse->_answer.begin(); iter < _lastResponse->_answer.end(); iter++){
	
		ResourceRecord& r = *iter;
		r._cacheExpireTime = _startTime + r._ttl;
		insertRecordIntoCache(r);
	
	}
	
	for(auto iter = _lastResponse->_authority.begin(); iter < _lastResponse->_authority.end(); iter++){
	
		ResourceRecord& r = *iter;
		r._cacheExpireTime = _startTime + r._ttl;
		insertRecordIntoCache(r);
	
	}
	
	for(auto iter = _lastResponse->_additional.begin(); iter < _lastResponse->_additional.end(); iter++){
	
		ResourceRecord& r = *iter;
		r._cacheExpireTime = _startTime + r._ttl;
		insertRecordIntoCache(r);
	
	}
	

}


void sendStandardQuery(string nameServerIp, shared_ptr<QueryState>& state){


	DNSFlags flg((uint8_t)qrVals::query, (uint8_t) opcodes::standard, 0, 0, 0, 0, 0, 0);
	DNSHeader hdr(id, flg, 1, 0, 0,0);
	QuestionRecord q(state._sname.c_str(), state._stype , state._sclass );
	
	vector<QuestionRecord> qr = {q};
	vector<ResourceRecord> rr;
	DNSMessage msg(hdr, qr, rr, rr, rr );
	
	vector<uint8_t> buff;
	vector<uint8_t> resp;
	msg.toBuffer(buff);

	int networkResult = sendMessageResolverClient(nameServerIp, buff, resp);
	
	if(networkResult == (int) NetworkCodes::none){
		auto iter = resp.begin();
		state->_lastResponse = make_shared<DNSMessage>(iter, iter, resp.end());
	
	}

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
	else cacheRecords();
	
	vector<uint8_t> msgBuff;
	_lastResponse.toBuffer(msgBuff);
	
	uint16_t numAnswersClaim = resp._hdr._numAnswers;
	size_t numAnswersActual = resp._answer.size();
	//dont need to bother checking if they dont claim there are any answers. But dont trust the claimed number for looping, could be huge or at least incorrect.
	if(numAnswersClaim > 0){
		
		for(size_t i =0; i < numAnswersActual; i++){
			ResourceRecord r = resp._answer[i];
			if( r._rType == (uint16_t)ResourceTypes::a){
			
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
			if( r._rType == (uint16_t)ResourceTypes::ns){
				string domain = ResourceRecord::getNSData(msgBuff, r._rData);
				pair<string, string> p("",domain);
				authMaps.push_back(p);
			}
		
		}
	
	}
	
	/*uint16_t numAdditClaim = resp._hdr._numAdditRR;
	size_t numAdditActual = resp._additional.size();
	if(numAdditClaim > 0){
		
		for(size_t i =0; i < numAdditActual; i++){
			ResourceRecord r = resp._additional[i];
			if( r._rType == (uint8_t)ResourceTypes::a){
			
			}
		
		}
		
		return SessionStates::continued;
	
	}*/
	
	
	
	return SessionStates::failed;

} 

void splitDomainName(string domainName, vector<string>& splits){
	
	
	bool labelsLeft = true;

	while(labelsLeft){
		
		size_t ind = domainName.find(".");
		if(ind == string::npos){
			labelsLeft = false;
			splits.push_back(domainName);
		}
		else{
			splits.push_back(domainName.substr(0,ind));
			domainName = domainName.substr(ind + 1);
		
		}
		
	}
	
	//needs one last split for the root
	splits.push_back("");


}

void solveStandardQuery(QueryState& query){

	//check cache directly for answers for this query. If we find any, we are done.
	list<ResourceRecord> directCached = getRecordsFromCache(query._sname);
	for(auto iter = directCached.begin(); iter < directCached.end(); iter++){
	
		ResourceRecord r = *iter;
		if(r._rType == (uint16_t) ResourceTypes::a){
			query._answers.push_back(r);
		
		}	
	}
	
	if(query._answers.size() > 0){
	
		return;
	
	}
	
	vector<string> splits;
	splitDomainName(query._sname, splits);
	//walking the current domain and ancestor domains to look for nameserver domain names we might want to consult, since we dont have an answer yet.
	for(size_t i = 0; i < splits.size(); i++){
		
		string currDomain;
		for(size_t j = i; j < splits.size(); j++){
			
			currDomain += splits[j];
			if(j != splits.size() - 1){
				currDomain += ".";
			}
			//root
			else if(j == i) currDomain += ".";
		
		}
		
		
		list<ResourceRecord> indirectCached = getRecordsFromCache(currDomain);
	
		for(auto iter = directCached.begin(); iter < directCached.end(); iter++){
	
			ResourceRecord r = *iter;
			if(r._rType == (uint16_t) ResourceTypes::ns){
			
				string domainName = r.getDataAsString();
				vector<QueryState>& servs = query._nextServers;
				
				//dont want to add the same domain name of a name server multiple times if there are multiple ns records.
				bool isUniqueName = true;
				for (auto servIter = servs.begin(); servIter < servs.end(); servIter++){
					if(servIter->_sname == domainName){
						isUniqueName = false;
						break;
					
					}
				}
				
				if(isUniqueName) query._nextServers.push_back(QueryState(domainName, query._stype, query._sclass));
			}
	
	
		}
	
	}
	
	//try to match addresses to these name servers we just identified.

	vector<QueryState>& servs = query._nextServers;
	for(auto nsIter = servs.begin(); nsIter < servs.end(); nsIter++){
	
		QueryState& inf = *nsIter;
		string currDomain = inf._sname;
		
		list<ResourceRecord> matchCached = getRecordsFromCache(currDomain);
		
		for(auto iter = matchCached.begin(); iter < matchCached.end(); iter++){

			ResourceRecord r = *iter;
			if(r._rType == (uint16_t) ResourceTypes::a){
			
				inf._answers.push_back(r);
			}
			
		}		
		
	}
	
	
	
	// start multithreaded resolution of the name servers we want to investigate but dont have an ip for
	
	vector<NameServerInfo>& nextServers = query._nextServers;
	for(auto nsIter = nextServers.begin(); nsIter < nextServers.end(); nsIter++){
	
		QueryState& inf = *nsIter;
		
		if(inf._answers.size() < 1){
		
			 pid_t pid = fork();
			 
			 if(pid < 0){
			 
			 	exit(EXIT_FAILURE)
			 }
			 //child process will resolve name server answer in background
			 //parent process will keep looping and eventually continue on to asking name servers(whose ips are being resolved in the background) for its own answer.
			 else if (pid == 0){
			 
			 	solveStandardQuery(inf);
			 	exit(0);
			 
			 }
			 
		
		}
			
	}

	





	
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

