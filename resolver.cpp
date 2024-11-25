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

unordered_map<string, list<ResourceRecord>> cache;

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

QueryState::QueryState(std::string sname, uint16_t stype, uint16_t sclass): _id(id), _sname(sname), _stype(stype), _sclass(sclass){ 

	_readyForUse = true;
	_networkCode = (int) NetworkErrors::none;
	_msgCode = (uint8_t) ResponseCodes::none;
	_startTime = time(NULL);
	_id = pickNextId();
}

QueryState::QueryState(std::string sname, uint16_t stype, uint16_t sclass, shared_ptr<int> globalOps): _id(id), _sname(sname), _stype(stype), _sclass(sclass) {

	_readyForUse = true;
	_networkCode = (int) NetworkErrors::none;
	_msgCode = (uint8_t) ResponseCodes::none;
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
		list<ResourceRecord>& records = cache[r._realName()];
		records.push_back(r);
	}

}

list<ResourceRecord> getRecordsFromCache(string domainName){

	if(cache.find(domainName) != cache.end()){
		list<ResourceRecord>& records = cache[r._realName];
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
QueryState::cacheRecords(DNSMessage& msg){

	for(auto iter = msg._answer.begin(); iter < msg._answer.end(); iter++){
	
		ResourceRecord& r = *iter;
		r._cacheExpireTime = _startTime + r._ttl;
		insertRecordIntoCache(r);
	
	}
	
	for(auto iter = msg._authority.begin(); iter < msg._authority.end(); iter++){
	
		ResourceRecord& r = *iter;
		r._cacheExpireTime = _startTime + r._ttl;
		insertRecordIntoCache(r);
	
	}
	
	for(auto iter = msg._additional.begin(); iter < msg._additional.end(); iter++){
	
		ResourceRecord& r = *iter;
		r._cacheExpireTime = _startTime + r._ttl;
		insertRecordIntoCache(r);
	
	}
	

}

bool QueryState::checkForResponseErrors(DNSMessage& resp){


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

void QueryState::extractDataFromResponse(DNSMessage& msg){


	if(checkForResponseErrors()) return;
	else cacheRecords();
	
	
	uint16_t numAnswersClaim = msg._hdr._numAnswers;
	size_t numAnswersActual = msg._answer.size();
	//dont need to bother checking if they dont claim there are any answers. But dont trust the claimed number for looping, could be huge or at least incorrect.
	if(numAnswersClaim > 0){
		
		for(size_t i =0; i < numAnswersActual; i++){
			ResourceRecord r = msg._answer[i];
			if(r._rType == (uint16_t) ResourceTypes::a){
				_answers.push_back(r);
			}
		
		}
		
		if(_answers.size() > 0){
			return;
		}
	
	}
	
	uint16_t numAuthClaim = msg._hdr._numAuthRR;
	size_t numAuthActual = msg._authority.size();
	if(numAuthClaim > 0){
	
		for(size_t i =0; i < numAuthActual; i++){
			ResourceRecord r = msg._authority[i];
			if(r._rType == (uint16_t) ResourceTypes::a){
				_answers.push_back(r);
			}
			if(r._rType == (uint16_t) ResourceTypes::ns){
				_answers.push_back(r);
			}
		}
	
	}
	
	uint16_t numAdditClaim = msg._hdr._numAdditRR;
	size_t numAdditActual = msg._additional.size();
	if(numAdditClaim > 0){
		
		for(size_t i =0; i < numAdditActual; i++){
			ResourceRecord r = msg._additional[i];
			r.affectNextServersData(this);
		
		}
		
	}
	
} 


void sendStandardQuery(string nameServerIp, QueryState& state){


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
	
	state._networkCode = networkResult;
	
	if(networkResult == (int) NetworkCodes::none){
		auto iter = resp.begin();
		DNSMessage msg = DNSMessage(iter, iter, resp.end());
		state._msgCode = msg._hdr._flags._rcode;
		
		state.extractDataFromResponse(msg);
	
	}
	

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

	query._readyForUse = false;

	//check cache directly for answers for this query. If we find any, we are done.
	list<ResourceRecord> directCached = getRecordsFromCache(query._sname);
	
	for(auto iter = directCached.begin(); iter < directCached.end(); iter++){
	
		ResourceRecord r = *iter;
		r.affectAnswers(&query);
		
	}
	
	if(query._answers.size() > 0){
		query._readyForUse = true; 
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
			r.affectNextServersNames(&query);
	
	
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
			r.affectNextServersData(&query);
			
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
	
	
	
	//one thread devoted to each nameserver for resolving the current query.
	//if a nameserver does not yet have an address(and it isnt currently being investigated by threads from above), use the nameserver's thread to resolve its address.
	//if a nameserver has multiple ips on record, they are all investigated on the same thread for simplicity.
	vector<NameServerInfo>& nsServers = query._nextServers;
	for(auto nsIter = nsServers.begin(); nsIter < nsServers.end(); nsIter++){
	
		pid_t pid = fork();
			 
		if(pid < 0){
			exit(EXIT_FAILURE)
		}
		//child process will resolve name server answer in background
		//parent process will keep looping and eventually continue on to asking name servers(whose ips are being resolved in the background) for its own answer.
		else if (pid == 0){
		
			QueryState& inf = *nsIter;
			
			if(inf._readyForUse && inf._numOpsLocalLeft > 0){
			
				//ready for use yet no answers available. This means it got added on the fly and still needs an address
				if(inf._answers.size() < 1){
					solveStandardQuery(inf);
				}
				else{
					vector<ResourceRecords
					for(auto ansIter = 
				
				}
			
			}
			
			solveStandardQuery(inf);
			exit(0);
			 
		}
			
			
	}
		

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

