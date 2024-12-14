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
#include <mutex>
#include <thread>
#include <sstream>

using namespace std;

vector<pair<string,string>> safety;

mutex idMutex;
vector<uint16_t> takenIds;

mutex cacheMutex;
unordered_map<string, vector< shared_ptr<ResourceRecord> > > cache;

thread::id mainThread = this_thread::get_id();


void dumpCacheToFile(){

	ofstream ot("cacheDump.txt");
	
	for(auto iter = cache.begin(); iter != cache.end(); iter++){
		
		vector<shared_ptr<ResourceRecord> >& lr = iter->second;
		
		for(auto iterR = lr.begin(); iterR < lr.end(); iterR++){
			stringstream s;
			shared_ptr<ResourceRecord>& r = *iterR;
			r->buildString(s);
			string str = s.str();
			ot << str << endl;
		}
	
	
	}
	
	
}


uint16_t pickNextId(){
	
	idMutex.lock();
	uint16_t max = 0;
	for(auto iter = takenIds.begin(); iter < takenIds.end(); iter++){
		if(*iter > max) max = *iter;
	
	}
	takenIds.push_back(max + 1);
	idMutex.unlock();
	return max + 1;

}

void reclaimId(uint16_t id){
	
	idMutex.lock();
	auto iter = takenIds.begin();
	bool found = false;
	for(; iter < takenIds.end(); iter++){
		if(*iter == id){
			found = true;
			break;
		}
	
	}
	
	if(found){
		takenIds.erase(iter);
	}
	idMutex.unlock();

}

QueryState::~QueryState(){

	reclaimId(_id);

}

QueryState::QueryState(string sname, uint16_t stype, uint16_t sclass): _sname(sname), _stype(stype), _sclass(sclass){ 

	
	_numOpsLocalLeft = perSequenceOpCap;
	 _numOpsGlobalLeft = make_shared<unsigned int>(perSequenceOpCap);
	
	_opMutex = make_shared<std::mutex>();
	_ansMutex = make_shared<std::mutex>();
	_servMutex = make_shared<std::mutex>();
	
	_readyForUse = true;
	_networkCode = (int) NetworkErrors::none;
	_msgCode = (uint8_t) ResponseCodes::none;
	_startTime = time(NULL);
	_id = pickNextId();
}

QueryState::QueryState(string sname, uint16_t stype, uint16_t sclass, QueryState& q): _sname(sname), _stype(stype), _sclass(sclass){ 

	_numOpsLocalLeft = perQueryOpCap;
	
	//shared pointer reference counts are thread safe, so dont need to guard anything for copying
	_opMutex = q._opMutex;
	_ansMutex = q._ansMutex;
	_servMutex = q._servMutex;
	
	 _numOpsGlobalLeft = q._numOpsGlobalLeft;
	
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
			//cout << "Invalid safety belt file format: line is missing semi colon" << endl;
		
		}
		else{
			
			string ipAddress = currLine.substr(0,delimPos);
			string domainName = currLine.substr(delimPos+1);
			pair<string,string> pr(ipAddress, domainName);
			safety.push_back(pr);
		
		}

	
	}
	
}



void insertRecordIntoCache(shared_ptr<ResourceRecord>& r){

	//if a ttl of 0, shouldnt cache it globally. This record will be cached locally for the query in the DNSMessage itself.
	if(r->_ttl > 0){
		cacheMutex.lock();
		vector<shared_ptr<ResourceRecord> >& records = cache[r->_realName];
		records.push_back(r);
		cacheMutex.unlock();
	}

}

//this method does not have mutex locking in it. the calling context is expected to lock instead in order to use the returned vector of records safely
vector<shared_ptr<ResourceRecord> >* getRecordsFromCache(string domainName){

	vector<shared_ptr<ResourceRecord> >* lr = NULL;
	
	if(cache.find(domainName) != cache.end()){
	
		vector<shared_ptr<ResourceRecord> >& records = cache[domainName];
		
		for(auto iter = records.begin(); iter < records.end(); iter++){
			shared_ptr<ResourceRecord> r = *iter;
			if(r->_cacheExpireTime < time(NULL)){
				records.erase(iter);
			}
		
		}
		
		lr = &records;
	}
	return lr;
	

}


//assumes errors have been checked for in the response(Dont want to cache any records that come from a bad response).
void QueryState::cacheRecords(DNSMessage& msg){

	cout << "caching records " << endl;

	for(auto iter = msg._answer.begin(); iter < msg._answer.end(); iter++){
	
		shared_ptr<ResourceRecord>& r = *iter;
		r->_cacheExpireTime = _startTime + r->_ttl;
		insertRecordIntoCache(r);
	
	}
	
	for(auto iter = msg._authority.begin(); iter < msg._authority.end(); iter++){
	
		shared_ptr<ResourceRecord>& r = *iter;
		r->_cacheExpireTime = _startTime + r->_ttl;
		insertRecordIntoCache(r);
	
	}
	
	for(auto iter = msg._additional.begin(); iter < msg._additional.end(); iter++){
	
		shared_ptr<ResourceRecord>& r = *iter;
		r->_cacheExpireTime = _startTime + r->_ttl;
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

bool QueryState::checkForFatalErrors(){


	if(_msgCode == (uint8_t) ResponseCodes::name){
	
		return true;
	
	}
	

	return false;

}


void QueryState::expandAnswers(string answer){
		
	_ansMutex->lock();
	bool unique = true;
	for(auto iter = _answers.begin(); iter < _answers.end(); iter++){
		if(*iter == answer){
			unique = false;
			break;
		
		}
	
	}
	if(unique) _answers.push_back(answer);
	_ansMutex->unlock();
	

}


void QueryState::expandNextServers(string domainName){

	vector<QueryState>& servs = _nextServers;
				
	//dont want to add the same domain name of a name server multiple times if there are multiple ns records.
	_servMutex->lock();
	bool isUniqueName = true;
	for (auto servIter = servs.begin(); servIter < servs.end(); servIter++){
		if(servIter->_sname == domainName){
			isUniqueName = false;
			break;
					
		}
	}			
	if(isUniqueName){
		cout << domainName << " unique " << endl;
		 _nextServers.emplace_back(domainName, _stype, _sclass, *this);
	}
	else{
		cout << domainName << " not unique " <<endl;
	
	}
	_servMutex->unlock();

}



void QueryState::expandNextServerAnswer(string domainName, string answer){

	vector<QueryState>& servs = _nextServers;
				
	_servMutex->lock();
	for (auto servIter = servs.begin(); servIter < servs.end(); servIter++){
		if(servIter->_sname == domainName){
			servIter->expandAnswers(answer);
					
		}
	}
	_servMutex->unlock();
		
}



void QueryState::extractDataFromResponse(DNSMessage& msg){

	//msg.print();


	if(checkForResponseErrors(msg)) return;
	else cacheRecords(msg);
	cout << "CACHE SIZE " << msg._hdr._transId << " " << cache.size() << endl; 
	
	
	uint16_t numAnswersClaim = msg._hdr._numAnswers;
	size_t numAnswersActual = msg._answer.size();
	//dont need to bother checking if they dont claim there are any answers. But dont trust the claimed number for looping, could be huge or at least incorrect.
	if(numAnswersClaim > 0){
		
		for(size_t i =0; i < numAnswersActual; i++){
			msg._answer[i]->affectAnswers(this);
		
		}
		
		if(_answers.size() > 0){
			_numOpsLocalLeft=0;
			return;
		}
	
	}
	
	uint16_t numAuthClaim = msg._hdr._numAuthRR;
	size_t numAuthActual = msg._authority.size();
	if(numAuthClaim > 0){
		for(size_t i =0; i < numAuthActual; i++){
			msg._authority[i]->affectNameServers(this);
		}
	
	}
	
	uint16_t numAdditClaim = msg._hdr._numAdditRR;
	size_t numAdditActual = msg._additional.size();
	if(numAdditClaim > 0){
		
		for(size_t i =0; i < numAdditActual; i++){
			msg._additional[i]->affectNameServers(this);
		
		}
		
	}
	
} 

void decrementOps(QueryState* q){

	unsigned int& opsL = q->_numOpsLocalLeft;
	if(opsL > 0){
		opsL = opsL - 1;
	}

	q->_opMutex->lock();
	
	unsigned int& opsG = *(q->_numOpsGlobalLeft);
	if(opsG > 0){
		opsG = opsG - 1;
	}
	
	q->_opMutex->unlock();

}

bool QueryState::haveLocalOpsLeft(){

	return (_numOpsLocalLeft >= 1);
}

bool QueryState::haveGlobalOpsLeft(){

	unsigned int gOps;
	_opMutex->lock();
	gOps = *_numOpsGlobalLeft;
	_opMutex->unlock();
	return (gOps >= 1);

}


void sendStandardQuery(string nameServerIp, QueryState* state){

	decrementOps(state);
	if(!state->haveLocalOpsLeft() || !state->haveGlobalOpsLeft()) return;
		
	
	DNSFlags flg((uint8_t)qrVals::query, (uint8_t) opcodes::standard, 0, 0, 0, 0, 0, 0);
	DNSHeader hdr(state->_id, flg, 1, 0, 0,0);
	QuestionRecord q(state->_sname.c_str(), state->_stype , state->_sclass );
	
	vector<QuestionRecord> qr = {q};
	vector<shared_ptr<ResourceRecord>> rr;
	DNSMessage msg(hdr, qr, rr, rr, rr );
	
	vector<uint8_t> buff;
	vector<uint8_t> resp;
	msg.toBuffer(buff);

	int networkResult = sendMessageResolverClient(nameServerIp, buff, resp);
	
	state->_networkCode = networkResult;
	
	if(networkResult == (int) NetworkErrors::none){
		auto iter = resp.begin();
		DNSMessage msg = DNSMessage(iter, iter, resp.end());
		state->_msgCode = msg._hdr._flags._rcode;
		
		state->extractDataFromResponse(msg);
	
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

void solveStandardQuery(QueryState* query){

	//cout << "SOLVING QUERY " << query._sname << endl;
	query->_readyForUse = false;

	//cout << "checking direct cache " << query._sname << endl;
	//check cache directly for answers for this query. If we find any, we are done.
	cacheMutex.lock();
	vector<shared_ptr<ResourceRecord> >* directCached = getRecordsFromCache(query->_sname);
	if(directCached != NULL){
		for(auto iter = directCached->begin(); iter < directCached->end(); iter++){
	
			shared_ptr<ResourceRecord> r = *iter;
			r->affectAnswers(query);
		
		}
	}
	cacheMutex.unlock();
	
	query->_ansMutex->lock();
	size_t ansSize = query->_answers.size();
	query->_ansMutex->unlock();
	
	if(ansSize > 0){
		query->_readyForUse = true; 
		return; 
	}
	
	vector<string> splits;
	splitDomainName(query->_sname, splits);
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
		
		//cout << "checking indirect cache " << query._sname << endl;
		cacheMutex.lock();
		vector<shared_ptr<ResourceRecord> >* indirectCached = getRecordsFromCache(currDomain);
		if(indirectCached != NULL){
			for(auto iter = indirectCached->begin(); iter < indirectCached->end(); iter++){
	
				shared_ptr<ResourceRecord> r = *iter;
				r->affectNameServers(query);
			}
		}
		cacheMutex.unlock();
	
	}
	
	//cout << "adding safeties" << query._sname << endl;
	//add safety belt servers on at the end, these are assumed to be correct so no further investigation needed.
	for(auto safetyIter = safety.begin(); safetyIter < safety.end(); safetyIter++){
	
		pair<string, string> safeNs = *safetyIter;
		query->expandNextServers(safeNs.second);
		query->expandNextServerAnswer(safeNs.second, safeNs.first);
	
	}
		
	//one thread devoted to each nameserver for resolving the current query.
	//if a nameserver does not yet have an address, use the nameserver's thread to resolve its address.
	//if a nameserver has multiple ips on record, they are all investigated on the same thread for simplicity.
	//cout << "asking nameservers " << query._sname << endl;
	size_t servIndex = 0;
	
	while(true){
	
		vector<QueryState>& nsServers = query->_nextServers;
		query->_servMutex->lock();
		size_t servSize = nsServers.size();
		cout << servSize << endl;
		if(servIndex >= servSize){
			servIndex = 0;
			query->_servMutex->unlock();
			continue;
		}
		QueryState& currS = nsServers[servIndex];
		query->_servMutex->unlock();
		
		//cout << "here " <<endl;
		decrementOps(query);
		if(query->haveLocalOpsLeft() && query->haveGlobalOpsLeft()){
		
			//cout << query._sname << " has ops left" << endl;
		
			thread workThr( [&](){
			
			
				if(currS._readyForUse){
				
					cout << query->_sname << " ns " << currS._sname << " ready for use" << endl;
			
					if(currS._answers.size() < 1){
						solveStandardQuery(&currS);
					}
					else{
					
						vector<string>& nsAns = currS._answers;
						size_t ansIndex = 0;
						while(true){
						
							currS._ansMutex->lock();
							size_t ansSize = nsAns.size();
							if(ansIndex >= ansSize){
								currS._ansMutex->unlock();
								break;
							}
							string ans = nsAns[ansIndex];
							currS._ansMutex->unlock();
							
							//cout << "Answering " << query._sname << " with " << ans << " " << currS._sname << " id " << currS._id << endl;
							sendStandardQuery(ans, query);
							ansIndex++;
							
						}
				
					}
			
				}
				
			});
			
			workThr.detach();	 
			servIndex++;	 
		}
		else{
		
			break;
		
		}
		
	}
	

	
}



