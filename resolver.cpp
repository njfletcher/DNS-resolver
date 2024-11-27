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
#include <mutex>
#include <thread>

using namespace std;

vector<uint16_t> takenIds();
vector<pair<string,string> > safety;
std::mutex opMutex;
std::mutex idMutex;
std::mutex cacheMutex;

//number of operations left for the series of requests that led to this one until failure
//0 means sequence has terminated. Same reasons as above.
unsigned int numOpsGlobalLeft = perSequenceOpCap;

unordered_map<string, list< std::shared_ptr<ResourceRecord> > > cache();

uint16_t pickNextId(){
	
	idMutex.lock();
	uint16_t max = 0;
	for(auto iter = takenIds.begin(); iter < takenIds.end(); iter++){
		if(*iter > max) max = *iter;
	
	}
	idMutex.unlock();
	return max + 1;

}

void reclaimId(uint16_t id){
	
	idMutex.lock();
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
	idMutex.unlock();

}

QueryState::~QueryState(){

	reclaimId(_id);

}

QueryState::QueryState(std::string sname, uint16_t stype, uint16_t sclass, bool isRoot): _id(id), _sname(sname), _stype(stype), _sclass(sclass){ 

	if(isRoot){
		_numOpsLocalLeft = perSequenceOpCap;
	}
	else{
		_numOpsLocalLeft = perQueryOpCap;
	}
	
	_readyForUse = true;
	_networkCode = (int) NetworkErrors::none;
	_msgCode = (uint8_t) ResponseCodes::none;
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
		cacheMutex.lock();
		list<shared_ptr<ResourceRecord> >& records = cache[r._realName()];
		records.push_back();
		cacheMutex.unlock();
	}

}

list<shared_ptr<ResourceRecord> >* getRecordsFromCache(string domainName){

	list<shared_ptr<ResourceRecord> >* lr = NULL;
	
	cacheMutex.lock();
	if(cache.find(domainName) != cache.end()){
	
		list<shared_ptr<ResourceRecord> >& records = cache[r._realName];
		
		for(auto iter = records.begin(); iter < records.end(); iter++){
			shared_ptr<ResourceRecord> r = *iter;
			if(r._cacheExpireTime < time(NULL)){
				records.erase(iter);
			}
		
		}
		
		lr = &records;
	}
	cacheMutex.unlock();
	return lr;
	

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

bool QueryState::checkForFatalErrors(QueryState& q){


	if(q._msgCode == (uint8_t) ResponseCodes::name){
	
		return true;
	
	}
	

	return false;

}

void QueryState::expandAnswers(shared_ptr<ResourceRecord> r){
	
	if(r->_rType != (uint16_t) ResourceTypes::a){
		return;
	}
	
	_answers.push_back(r->getDataAsString());
	

}

void QueryState::expandNextServers(shared_ptr<ResourceRecord> r){

	if(r->_rType != (uint16_t) ResourceTypes::ns){
		return;
	}

	string domainName = r->getDataAsString();
	vector<QueryState>& servs = _nextServers;
				
	//dont want to add the same domain name of a name server multiple times if there are multiple ns records.
	bool isUniqueName = true;
	for (auto servIter = servs.begin(); servIter < servs.end(); servIter++){
		if(servIter->_sname == domainName){
			isUniqueName = false;
			break;
					
		}
	}
				
	if(isUniqueName) _nextServers.emplace_back(domainName, _stype, _sclass, false);


}

void QueryState::expandNextServerAnswer(shared_ptr<ResourceRecord> r){

	if(r->_rType != (uint16_t) ResourceTypes::a){
		return;
	}
	
	string domainName = r->_realName;
	vector<QueryState>& servs = _nextServers;
				
	for (auto servIter = servs.begin(); servIter < servs.end(); servIter++){
		if(servIter->_sname == domainName){
			servIter->answers.push_back(r->getDataAsString());
					
		}
	}
				
}



void QueryState::extractDataFromResponse(DNSMessage& msg){


	if(checkForResponseErrors()) return;
	else cacheRecords();
	
	
	uint16_t numAnswersClaim = msg._hdr._numAnswers;
	size_t numAnswersActual = msg._answer.size();
	//dont need to bother checking if they dont claim there are any answers. But dont trust the claimed number for looping, could be huge or at least incorrect.
	if(numAnswersClaim > 0){
		
		for(size_t i =0; i < numAnswersActual; i++){
			shared_ptr<ResourceRecord> r = msg._answer[i];
			expandAnswers(r);
		
		}
		
		if(_answers.size() > 0){
			return;
		}
	
	}
	
	uint16_t numAuthClaim = msg._hdr._numAuthRR;
	size_t numAuthActual = msg._authority.size();
	if(numAuthClaim > 0){
		for(size_t i =0; i < numAuthActual; i++){
			shared_ptr<ResourceRecord> r = msg._authority[i];
			expandNextServerAnswer(r);
			expandNextServers(r);
		}
	
	}
	
	uint16_t numAdditClaim = msg._hdr._numAdditRR;
	size_t numAdditActual = msg._additional.size();
	if(numAdditClaim > 0){
		
		for(size_t i =0; i < numAdditActual; i++){
			shared_ptr<ResourceRecord> r = msg._additional[i];
			expandNextServerAnswer(r);
		
		}
		
	}
	
} 

void decrementOps(QueryState& q){

	unsigned int& opsL = q._numLocalOpsLeft;
	if(opsL > 0){
		opsL = opsL - 1;
	}

	queryMutex.lock();
	
	unsigned int& opsG = numGlobalOpsLeft;
	if(opsG > 0){
		opsG = opsG - 1;
	}
	
	queryMutex.unlock();

}

bool haveOpsLeft(QueryState& q){

	unsigned int gOps;
	queryMutex.lock();
	gOps = numOpsGlobalLeft;
	queryMutex.unlock();
	
	if(state._numOpsLocalLeft < 1 || gOps < 1){
		return false;
	}
	else return true;

}


void sendStandardQuery(string nameServerIp, QueryState& state){

	decrementOps(state);
	if(!haveOpsLeft) return;
	
	
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
	list<shared_ptr<ResourceRecord> >* directCached = getRecordsFromCache(query._sname);
	if(directCached != NULL){
		for(auto iter = directCached->begin(); iter < directCached->end(); iter++){
	
			shared_ptr<ResourceRecord> r = *iter;
			query.expandAnswers(r);
		
		}
	
		if(query._answers.size() > 0){
			query._readyForUse = true; 
			return; 
		}
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
		
		
		list<shared_ptr<ResourceRecord> >* indirectCached = getRecordsFromCache(currDomain);
	
		if(indirectCached != NULL){
			for(auto iter = indirectCached->begin(); iter < indirectCached->end(); iter++){
	
				shared_ptr<ResourceRecord> r = *iter;
				query.expandNextServers(r);
			}
		}
	
	}
	
	//try to match addresses to these name servers we just identified.

	vector<QueryState>& servs = query._nextServers;
	for(auto nsIter = servs.begin(); nsIter < servs.end(); nsIter++){
	
		QueryState& inf = *nsIter;
		string currDomain = inf._sname;
		
		list<shared_ptr<ResourceRecord> >* matchCached = getRecordsFromCache(currDomain);
		
		if(matchCached != NULL){
			for(auto iter = matchCached->begin(); iter < matchCached->end(); iter++){

				shared_ptr<ResourceRecord> r = *iter;
				inf.expandAnswers(r);
			
			}
		}		
		
	}
	
	
	
	// start multithreaded resolution of the name servers we want to investigate but dont have an ip for
	vector<QueryState>& nextServers = query._nextServers;
	for(auto nsIter = nextServers.begin(); nsIter < nextServers.end(); nsIter++){
	
		QueryState& inf = *nsIter;
		
		if(inf._answers.size() < 1){
		
			decrementOps(query);
			if(haveOpsLeft()){
		
				pid_t pid = fork();
			 
				if(pid < 0){
			 
					exit(EXIT_FAILURE);
				}
				//child process will resolve name server answer in background
				//parent process will keep looping and eventually continue on to asking name servers(whose ips are being resolved in the background) for its own answer.
				else if (pid == 0){
			
					solveStandardQuery(inf);
					exit(0);
			 
				}
			}
			else return;	 
		}	
	}
	
	
	
	//one thread devoted to each nameserver for resolving the current query.
	//if a nameserver does not yet have an address(and it isnt currently being investigated by threads from above), use the nameserver's thread to resolve its address.
	//if a nameserver has multiple ips on record, they are all investigated on the same thread for simplicity.
	vector<QueryState>& nsServers = query._nextServers;
	for(auto nsIter = nsServers.begin(); nsIter < nsServers.end(); nsIter++){
	
		decrementOps(query);
		if(haveOpsLeft()){
			pid_t pid = fork();
			 
			if(pid < 0){
				exit(EXIT_FAILURE);
			}
			else if (pid == 0){
		
				QueryState& inf = *nsIter;
			
				if(inf._readyForUse){
			
					//ready for use yet no answers available. This means it got added on the fly and still needs an address
					if(inf._answers.size() < 1){
						solveStandardQuery(inf);
					}
					else{
					
						for(auto ansIter = inf._answers.begin(); ansIter < inf._answers.end(); ansIter++){
							sendStandardQuery(*ansIter, query);
							
						}
				
					}
			
				}
			
				exit(0);
			}
			 
		}
		else return;
			
	}
	
}



