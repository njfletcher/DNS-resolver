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

vector<thread> threads;
mutex threadMutex;

atomic<bool> moreThreads(true);


void QueryInstruction::affectQuery(QueryState& q, CNameResourceRecord& record, shared_ptr<ResourceRecord> recP, QueryContext cont){ return; }
void QueryInstruction::affectQuery(QueryState& q, AResourceRecord& record, shared_ptr<ResourceRecord> recP, QueryContext cont){ return; }
void QueryInstruction::affectQuery(QueryState& q, NSResourceRecord& record, shared_ptr<ResourceRecord> recP, QueryContext cont){ return; }
void QueryInstruction::affectQuery(QueryState& q, ResourceRecord& record, shared_ptr<ResourceRecord> recP, QueryContext cont){ return; }

void AQueryInstruction::affectQuery(QueryState& q, CNameResourceRecord& record, shared_ptr<ResourceRecord> recP, QueryContext cont){
	
	if(cont == QueryContext::answerSection){
		q.expandInfo(recP);
		q.redirectQuery(record.getName());
	}
	//dont care about cnames in authority or additional sections(if there are any). those are cached and irrelevant directly to this query.

}

void AQueryInstruction::affectQuery(QueryState& q, AResourceRecord& record, shared_ptr<ResourceRecord> recP, QueryContext cont){ 

	
	if(cont == QueryContext::answerSection){
		q.expandAnswers(recP);
		q.expandIps(record.getDataAsString());
	}
	
	if(cont == QueryContext::additionalSection){
		q.expandNextServerAnswer(recP);
		q.expandNextServerIps(record.getName(), record.getDataAsString());
	}


}
void AQueryInstruction::affectQuery(QueryState& q, NSResourceRecord& record, shared_ptr<ResourceRecord> recP, QueryContext cont){ 

	if(cont == QueryContext::authoritySection){
		q.expandNextServers(record.getDataAsString());
	}

}
void AQueryInstruction::affectQuery(QueryState& q, ResourceRecord& record, shared_ptr<ResourceRecord> recP, QueryContext cont){ return; }


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

void QueryState::redirectQuery(std::string sname){

	_sname = sname;
}

QueryState::QueryState(string sname, uint16_t stype, uint16_t sclass, shared_ptr<QueryInstruction> qI): _sname(sname), _stype(stype), _sclass(sclass), _inst(qI){ 


	_beingUsed.store(false);
	_id = pickNextId();
	_matchScore = 0;
	
	_startTime = time(NULL);
	
	_networkCode = (int) NetworkErrors::none;
	_msgCode = (uint8_t) ResponseCodes::none;
	
	_numOpsLocalLeft.store(perSequenceOpCap);
	_numOpsGlobalLeft = make_shared<atomic<int> >(perSequenceOpCap);
	
	_ansMutex = make_shared<std::mutex>();
	_servMutex = make_shared<std::mutex>();
	_infoMutex = make_shared<std::mutex>();
	
}

QueryState::QueryState(string sname, uint16_t stype, uint16_t sclass, QueryState* q): _sname(sname), _stype(stype), _sclass(sclass){ 

	_numOpsLocalLeft.store(perQueryOpCap);
	
	_ansMutex = make_shared<std::mutex>();
	_servMutex = make_shared<std::mutex>();
	_infoMutex = make_shared<std::mutex>();
	
	 _numOpsGlobalLeft = q->_numOpsGlobalLeft;
	
	_beingUsed.store(false);
	_networkCode = (int) NetworkErrors::none;
	_msgCode = (uint8_t) ResponseCodes::none;
	_startTime = time(NULL);
	_id = pickNextId();
	_inst = q->_inst;
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


void QueryState::expandAnswers(shared_ptr<ResourceRecord> rec){
		
	_ansMutex->lock();
	bool unique = true;
	for(auto iter = _answers.begin(); iter < _answers.end(); iter++){
		if(**iter == *rec){
			unique = false;
			break;
		
		}
	
	}
	if(unique) _answers.push_back(rec);
	_ansMutex->unlock();
	

}

void QueryState::expandIps(string ip){
		
	_ansMutex->lock();
	bool unique = true;
	for(auto iter = _ips.begin(); iter < _ips.end(); iter++){
		if(*iter == ip){
			unique = false;
			break;
		
		}
	
	}
	if(unique) _ips.push_back(ip);
	_ansMutex->unlock();
	

}

void QueryState::expandInfo(shared_ptr<ResourceRecord> rec){
		
	_infoMutex->lock();
	bool unique = true;
	for(auto iter = _extraInfo.begin(); iter < _extraInfo.end(); iter++){
		if(*iter == rec){
			unique = false;
			break;
		
		}
	
	}
	if(unique) _extraInfo.push_back(rec);
	_infoMutex->unlock();
	

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



void QueryState::expandNextServerAnswer(shared_ptr<ResourceRecord> answer){
			
	_servMutex->lock();
	for (auto servIter = _nextServers.begin(); servIter < _nextServers.end(); servIter++){
		shared_ptr<QueryState> q = *servIter;
		
		if(q->_sname == answer->getName()){
			q->expandAnswers(answer);
					
		}
	}
	_servMutex->unlock();
		
}

void QueryState::expandNextServerIps(string name, string ip){
			
	_servMutex->lock();
	for (auto servIter = _nextServers.begin(); servIter < _nextServers.end(); servIter++){
		shared_ptr<QueryState> q = *servIter;
		
		if(q->_sname == name){
			q->expandIps(ip);
					
		}
	}
	_servMutex->unlock();
		
}


void QueryState::decrementOps(){

	_numOpsLocalLeft.store(_numOpsLocalLeft.load() - 1);
	_numOpsGlobalLeft->store(_numOpsGlobalLeft->load() - 1);	

}

bool QueryState::haveLocalOpsLeft(){

	return (_numOpsLocalLeft.load() >= 1);
}

bool QueryState::haveGlobalOpsLeft(){

	return (_numOpsGlobalLeft->load() >= 1);
}

void QueryState::forceEndQuery(bool localOnly){

	_numOpsLocalLeft.store(0);

	if(!localOnly){
		_numOpsGlobalLeft->store(0);
	}

}


void QueryState::sendStandardQuery(shared_ptr<QueryState> query, string nameServerIp){

	DNSFlags flg((uint8_t)qrVals::query, (uint8_t) opcodes::standard, 0, 0, 0, 0, 0, 0);
	DNSHeader hdr(query->_id, flg, 1, 0, 0,0);
	QuestionRecord q(query->_sname.c_str(), query->_stype , query->_sclass);
	
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
	
	query->_networkCode = networkResult;
	
	if(networkResult == (int) NetworkErrors::none){
		auto iter = resp.begin();
		DNSMessage msg1(iter, iter, resp.end());
		if(!msg1.checkForResponseErrors(query->_id, query->_msgCode)){
			msg1.extractData(query, query->_startTime);
		}
	
	}
	
}

void splitDomainName(string domainName, vector<string>& splits, bool rev){
	
	
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
	if(rev) reverse(splits.begin(), splits.end());


}

bool QueryState::checkEndCondition(){

	bool end = false;
	
	if(!haveGlobalOpsLeft()) end = true;
	
	if(!haveLocalOpsLeft()) end = true;
	
	if(_msgCode == (uint8_t)ResponseCodes::name || _msgCode == (uint8_t)ResponseCodes::format) end = true;
	
	_ansMutex->lock();
	if(_answers.size() > 0) end = true;
	_ansMutex->unlock();
	
	_servMutex->lock();
	bool allServersDone = true;
	for(auto iter = _nextServers.begin(); iter < _nextServers.end(); iter++){
		shared_ptr<QueryState> qr = *iter;
		if(qr->haveLocalOpsLeft()){
			allServersDone = false;
			break;
		}
	}
	_servMutex->unlock();
	if(allServersDone) end = true;
	
	return end; 

}

void QueryState::displayResult(){


	printMutex.lock();
	if(!haveGlobalOpsLeft()){
		cout << "query ran out of global ops" << endl;
	
	}
	
	if(!haveLocalOpsLeft()){
		cout << "query ran out of local ops" << endl;
	
	}
	
	if(_msgCode == (uint8_t)ResponseCodes::name || _msgCode == (uint8_t)ResponseCodes::format){
	
		cout << "query encountered a fatal error" << endl;
	}
	
	_ansMutex->lock();
	if(_answers.size() > 0){
		cout << "query got answers : " << endl;
		for(auto iter = _answers.begin(); iter < _answers.end(); iter++){
		
			shared_ptr<ResourceRecord> r = *iter;
			cout << "ANSWER " << endl;
			r->print();
		}
	
	}
	_ansMutex->unlock();
	
	_servMutex->lock();
	bool allServersDone = true;
	for(auto iter = _nextServers.begin(); iter < _nextServers.end(); iter++){
		shared_ptr<QueryState> qr = *iter;
		if(qr->haveLocalOpsLeft()){
			allServersDone = false;
			break;
		}
	}
	_servMutex->unlock();
	
	if(allServersDone) cout << " all servers depleted " << endl;
	
	printMutex.unlock();
	
}

void QueryState::setMatchScore(string domainName){

	vector<string> refSplits;
	splitDomainName(domainName, refSplits, true);
	
	vector<string> ownSplits;
	splitDomainName(_sname, ownSplits, true);
	
	int score = 0;
	
	size_t refLen = refSplits.size();
	size_t ownLen = ownSplits.size();
	
	for(size_t i = 0, j = 0; i < refLen && j < ownLen; i++, j++){

		if(refSplits[i] == ownSplits[j]){
			score++;
		}
		else{
			break;
		}
	
	
	} 
	_matchScore = score;


}


void QueryState::threadFunction(shared_ptr<QueryState> currS, shared_ptr<QueryState> query){

	query->decrementOps();
	currS->_ansMutex->lock();
	vector<string> ips = currS->_ips;
	currS->_ansMutex->unlock();
	
		
	if(ips.size() < 1){
		QueryState::solveStandardQuery(currS);
	}
	else{
		for(auto iter = ips.begin(); iter < ips.end(); iter++){
			string ip = *iter;
			currS->decrementOps();
			QueryState::sendStandardQuery(query, ip);
			
		}	
		currS->forceEndQuery(true);
				
	}
					
}

void QueryState::solveStandardQuery(shared_ptr<QueryState> q){

	//printMutex.lock();
	//cout << "started resolving " << _sname << endl;
	//printMutex.unlock();
	
	q->_beingUsed.store(true);

	//check cache directly for answers for this query. If we find any, we are done.
	cacheMutex.lock();
	vector<shared_ptr<ResourceRecord> >* directCached = ResourceRecord::getRecordsFromCache(q->_sname);
	if(directCached != NULL){
		for(auto iter = directCached->begin(); iter < directCached->end(); iter++){
	
			shared_ptr<ResourceRecord> r = *iter;
			r->executeInstructions(r, QueryContext::answerSection, *q);
		
		}
	}
	cacheMutex.unlock();
	
	q->_ansMutex->lock();
	size_t ansSize = q->_answers.size();
	q->_ansMutex->unlock();
	
	if(ansSize > 0){
		q->_beingUsed.store(false); 
		return; 
	}
	
	vector<string> splits;
	splitDomainName(q->_sname, splits, false);
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
		vector<shared_ptr<ResourceRecord> >* indirectCached = ResourceRecord::getRecordsFromCache(currDomain);
		if(indirectCached != NULL){
			for(auto iter = indirectCached->begin(); iter < indirectCached->end(); iter++){
	
				shared_ptr<ResourceRecord> r = *iter;
				r->executeInstructions(r, QueryContext::authoritySection, *q);
				r->executeInstructions(r, QueryContext::additionalSection, *q);
			}
		}
		cacheMutex.unlock();
	
	}
	
	//add safety belt servers on at the end, these are assumed to be correct so no further investigation needed.
	for(auto safetyIter = safety.begin(); safetyIter < safety.end(); safetyIter++){
	
		pair<string, string> safeNs = *safetyIter;
		q->expandNextServers(safeNs.second);
		q->expandNextServerIps(safeNs.second, safeNs.first);
	
	}
	
	while(true){
	
		vector<shared_ptr<QueryState> > nextServers;
	
		q->_servMutex->lock();
		sort(q->_nextServers.begin(), q->_nextServers.end(), [](shared_ptr<QueryState> q1, shared_ptr<QueryState> q2){ return q1->_matchScore > q2->_matchScore;} );
		for(auto iter = q->_nextServers.begin(); iter < q->_nextServers.end(); iter++){
			shared_ptr<QueryState> ns = *iter;
			if(ns->haveLocalOpsLeft() && !ns->_beingUsed.load()){
				nextServers.push_back(ns);
				ns->_beingUsed.store(true);
			}
			
		}
		q->_servMutex->unlock();
		for(auto iter = nextServers.begin(); iter < nextServers.end(); iter++){
			
			shared_ptr<QueryState> currS = *iter;
			
			if(q->haveLocalOpsLeft() && q->haveGlobalOpsLeft() && moreThreads.load()){
				threadMutex.lock();
				threads.emplace_back(threadFunction, currS, q);
				threadMutex.unlock();
			}
				
			
		}
		
		//dumpCacheToFile();
		if(q->checkEndCondition()) break;
		if(!moreThreads.load()) break;
			
	}
	
	q->_beingUsed.store(false);
	
}



