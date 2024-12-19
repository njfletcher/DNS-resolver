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
#include <algorithm> 

using namespace std;

vector<pair<string,string>> safety;

mutex idMutex;
vector<uint16_t> takenIds;

mutex cacheMutex;
unordered_map<string, vector< shared_ptr<ResourceRecord> > > cache;

mutex printMutex;

void dumpCacheToFile(){

	ofstream ot("cacheDump.txt");
	
	cacheMutex.lock();
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
	cacheMutex.unlock();
	
	
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


	_readyForUse = true;
	_id = pickNextId();
	_matchScore = 0;
	
	_startTime = time(NULL);
	
	_networkCode = (int) NetworkErrors::none;
	_msgCode = (uint8_t) ResponseCodes::none;
	
	_numOpsLocalLeft = perSequenceOpCap;
	_numOpsGlobalLeft = make_shared<unsigned int>(perSequenceOpCap);
	
	_opMutex = make_shared<std::mutex>();
	_ansMutex = make_shared<std::mutex>();
	_servMutex = make_shared<std::mutex>();
	
}

QueryState::QueryState(string sname, uint16_t stype, uint16_t sclass, QueryState* q): _sname(sname), _stype(stype), _sclass(sclass){ 

	_numOpsLocalLeft = perQueryOpCap;
	
	_ansMutex = make_shared<std::mutex>();
	_servMutex = make_shared<std::mutex>();
	_opMutex = q->_opMutex;
	
	 _numOpsGlobalLeft = q->_numOpsGlobalLeft;
	
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
			
	//dont want to add the same domain name of a name server multiple times if there are multiple ns records.
	_servMutex->lock();
	bool isUniqueName = true;
	for (auto servIter = _nextServers.begin(); servIter < _nextServers.end(); servIter++){
		shared_ptr<QueryState> q = *servIter;
		
		if(q->_sname == domainName){
			isUniqueName = false;
			break;
					
		}
	}			
	if(isUniqueName){
		_nextServers.push_back(make_shared<QueryState>(domainName, _stype, _sclass, this));
		shared_ptr<QueryState> nQ = _nextServers[_nextServers.size()-1];
		nQ->setMatchScore(_sname);
	}
	_servMutex->unlock();

}



void QueryState::expandNextServerAnswer(string domainName, string answer){
			
	_servMutex->lock();
	for (auto servIter = _nextServers.begin(); servIter < _nextServers.end(); servIter++){
		shared_ptr<QueryState> q = *servIter;
		
		if(q->_sname == domainName){
			q->expandAnswers(answer);
					
		}
	}
	_servMutex->unlock();
		
}



void extractDataFromResponse(DNSMessage& msg, shared_ptr<QueryState> qr){

	if(qr->checkForResponseErrors(msg)) return;
	else qr->cacheRecords(msg);
	
	
	uint16_t numAnswersClaim = msg._hdr._numAnswers;
	size_t numAnswersActual = msg._answer.size();
	//dont need to bother checking if they dont claim there are any answers. But dont trust the claimed number for looping, could be huge or at least incorrect.
	if(numAnswersClaim > 0){
		
		for(size_t i =0; i < numAnswersActual; i++){
			msg._answer[i]->affectAnswers(qr);
		
		}
		
		if(qr->_answers.size() > 0){
			return;
		}
	
	}
	
	uint16_t numAuthClaim = msg._hdr._numAuthRR;
	size_t numAuthActual = msg._authority.size();
	if(numAuthClaim > 0){
		for(size_t i =0; i < numAuthActual; i++){
			msg._authority[i]->affectNameServers(qr);
		}
	
	}
	
	uint16_t numAdditClaim = msg._hdr._numAdditRR;
	size_t numAdditActual = msg._additional.size();
	if(numAdditClaim > 0){
		
		for(size_t i =0; i < numAdditActual; i++){
			msg._additional[i]->affectNameServers(qr);
		
		}
		
	}
	
} 

void QueryState::decrementOps(){

	unsigned int& opsL = _numOpsLocalLeft;
	if(opsL > 0){
		opsL = opsL - 1;
	}
	
	_opMutex->lock();
	unsigned int& opsG = *(_numOpsGlobalLeft);
	if(opsG > 0){
		opsG = opsG - 1;
	}
	_opMutex->unlock();


}

bool QueryState::haveLocalOpsLeft(){

	return (_numOpsLocalLeft >= 1);
}

bool QueryState::haveGlobalOpsLeft(){

	_opMutex->lock();
	unsigned int opsG = *_numOpsGlobalLeft;
	_opMutex->unlock();
	return (opsG >= 1);
}


void sendStandardQuery(string nameServerIp, shared_ptr<QueryState> state){

	DNSFlags flg((uint8_t)qrVals::query, (uint8_t) opcodes::standard, 0, 0, 0, 0, 0, 0);
	DNSHeader hdr(state->_id, flg, 1, 0, 0,0);
	QuestionRecord q(state->_sname.c_str(), state->_stype , state->_sclass );
	
	vector<QuestionRecord> qr;
	qr.push_back(q);
	vector<shared_ptr<ResourceRecord>> rr1;
	vector<shared_ptr<ResourceRecord>> rr2;
	vector<shared_ptr<ResourceRecord>> rr3;
	DNSMessage msg(hdr, qr, rr1, rr2, rr3);
	
	vector<uint8_t> buff;
	vector<uint8_t> resp;
	msg.toBuffer(buff);

	int networkResult = sendMessageResolverClient(nameServerIp, buff, resp);
	
	state->_networkCode = networkResult;
	
	if(networkResult == (int) NetworkErrors::none){
		auto iter = resp.begin();
		DNSMessage msg1(iter, iter, resp.end());
		state->_msgCode = msg1._hdr._flags._rcode;
		
		extractDataFromResponse(msg1,state);
	
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

bool QueryState::checkEndCondition(){

	bool end = false;
	
	if(!haveGlobalOpsLeft()) end = true;
	
	if(!haveLocalOpsLeft()) end = true;
	
	if(_msgCode == (uint8_t)ResponseCodes::name || _msgCode == (uint8_t)ResponseCodes::format) end = true;
	
	_ansMutex->lock();
	if(_answers.size() > 0) end = true;
	_ansMutex->unlock();
	
	return end; 

}

void displayResult(QueryState& q){


	printMutex.lock();
	if(!q.haveGlobalOpsLeft()){
		cout << "query ran out of global ops" << endl;
	
	}
	
	if(!q.haveLocalOpsLeft()){
		cout << "query ran out of local ops" << endl;
	
	}
	
	if(q._msgCode == (uint8_t)ResponseCodes::name || q._msgCode == (uint8_t)ResponseCodes::format){
	
		cout << "query encountered a fatal error" << endl;
	}
	
	q._ansMutex->lock();
	if(q._answers.size() > 0){
		cout << "query got answers : " << endl;
		for(auto iter = q._answers.begin(); iter< q._answers.end(); iter++){
		
			cout << "ANSWER " << *iter << endl;
		}
	
	}
	q._ansMutex->unlock();
	
	printMutex.unlock();
	
}

void QueryState::setMatchScore(string domainName){

	vector<string> refSplits;
	splitDomainName(domainName, refSplits);
	
	vector<string> ownSplits;
	splitDomainName(_sname, ownSplits);
	
	int score = 0;
	
	size_t refLen = refSplits.size();
	size_t ownLen = ownSplits.size();
	
	for(size_t i = refLen -1, j = ownLen -1; i >= 0 && j >=0; i--, j--){

		if(refSplits[i] == ownSplits[j]){
			score++;
		}
		else{
			break;
		}
	
	
	} 
	_matchScore = score;


}


void threadFunction(shared_ptr<QueryState> currS,shared_ptr<QueryState> query){

	decrementOps(query);
	vector<string> answers;
		
	currS->_ansMutex->lock();
	for(auto iter = currS->_answers.begin(); iter < currS->_answers.end(); iter++){
		answers.push_back(*iter);
		//printMutex.lock();
		//cout << "NS answer " << *iter << endl;
		//printMutex.unlock();
	}
	currS->_ansMutex->unlock();
		
	if(answers.size() < 1){
		solveStandardQuery(currS);
	}
	else{
		for(auto iter = answers.begin(); iter < answers.end(); iter++){
			string ans = *iter;
			decrementOps(currS);
			
			//printMutex.lock();
			//cout << "sending request to " << currS->_sname << "(" << ans << ") to solve " << query->_sname << endl;
			//printMutex.unlock();
			sendStandardQuery(ans, query);
			
		}	
		currS->_numOpsLocalLeft = 0;
				
	}
					
}

void QueryState::solveStandardQuery(){

	_beingUsed = true;

	//check cache directly for answers for this query. If we find any, we are done.
	cacheMutex.lock();
	vector<shared_ptr<ResourceRecord> >* directCached = getRecordsFromCache(_sname);
	if(directCached != NULL){
		for(auto iter = directCached->begin(); iter < directCached->end(); iter++){
	
			shared_ptr<ResourceRecord> r = *iter;
			r->affectAnswers(query);
		
		}
	}
	cacheMutex.unlock();
	
	_ansMutex->lock();
	size_t ansSize = _answers.size();
	_ansMutex->unlock();
	
	if(ansSize > 0){
		_beingUsed = false; 
		return; 
	}
	
	vector<string> splits;
	splitDomainName(_sname, splits);
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
	
	//add safety belt servers on at the end, these are assumed to be correct so no further investigation needed.
	for(auto safetyIter = safety.begin(); safetyIter < safety.end(); safetyIter++){
	
		pair<string, string> safeNs = *safetyIter;
		expandNextServers(safeNs.second);
		expandNextServerAnswer(safeNs.second, safeNs.first);
	
	}
	
	while(true){
	
		vector<shared_ptr<QueryState> > nextServers;
	
		_servMutex->lock();
		sort(_nextServers.begin(), _nextServers.end(), [](shared_ptr<QueryState> q1, shared_ptr<QueryState> q2){ return q1->_matchScore > q2->_matchScore;} );
		for(auto iter = _nextServers.begin(); iter < _nextServers.end(); iter++){
			shared_ptr<QueryState> ns = *iter;
			if(ns->haveLocalOpsLeft() && !ns->_beingUsed){
				nextServers.push_back(ns);
				ns->_beingUsed = true;
			}
			
		}
		_servMutex->unlock();
		for(auto iter = nextServers.begin(); iter < nextServers.end(); iter++){
			
			shared_ptr<QueryState> currS = *iter;
			
			if(haveLocalOpsLeft() && haveGlobalOpsLeft()){
				thread workThr(threadFunction, currS, query);
				workThr.detach();
			}
				
			
		}
		
		if(checkEndCondition(*query)) break;
			
	}
	
}



