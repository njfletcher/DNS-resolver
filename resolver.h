#pragma once

#include <string>
#include <utility>
#include <list>
#include <memory>
#include "structures.h"
#include <vector>
#include <ctime>
#include <mutex>
#include <thread>
#include <atomic>
#include <unordered_map>

#define maxDomainNameLen 255

//operation capping to make sure threads dont go out of control or network errors cause program to run forever.
//a thread spawn or network request is one operation decrement
#define perQueryOpCap 50
#define perSequenceOpCap 1000

class DNSMessage;
class ResourceRecord;
class AResourceRecord;
class NsResourceRecord;
class CNameResourceRecord;
class QueryState;

extern std::mutex cacheMutex;
extern std::unordered_map<std::string, std::vector< std::shared_ptr<ResourceRecord> > > cache;
extern std::mutex printMutex;

extern std::vector<std::thread> threads;
extern std::mutex threadMutex;

extern std::atomic<bool> moreThreads;



enum class qrVals{

	query = 0,
	response = 1

};

enum class opcodes{

	standard = 0, //a standard query (QUERY)
	inverse = 1, // an inverse query (IQUERY)
	status = 2 //a server status request (STATUS)

};

enum class ResourceTypes{

	a = 1, // a host address
	ns = 2, // an authoritative name server
	cname = 5, //the canonical name for an alias
	soa = 6, //marks the start of a zone of authority
	mb = 7, //a mailbox domain name
	mg = 8, // a mail group member
	mr = 9, // a mail rename domain name,
	nullR = 10, // a null resource record
	wks = 11, // a well known server description
	ptr = 12, // a domain name pointer
	hinfo = 13, // host information
	minfo = 14, //mailbox or mail list information
	mx = 15, //mail exchange
	txt = 16, //text strings
	afxr = 252, // a request for a transfer of an entire zone
	mailb = 253,//a request for mailbox related records( MB, MG, or MR)
	all = 255// a request for all records(*)

};

enum class ResourceClasses{

	in = 1, //the internet
	ch = 3, //the CHAOS class
	hs = 4, //Hesiod
	all = 255 //all classes

};

enum class ResponseCodes{

	none = 0, // no errors
	format = 1, // the name server was unable to interpret the query
	server = 2, //The name server was unable to process this query due to a problem with the name server
	name = 3, //Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does  not exist.
	implement = 4, //The name server does not support the requested kind of query
	refused = 5 //The name server refuses to perform the specified operation for policy reasons.  For example, 
	//a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data

};

enum class QueryContext{

	answerSection = 0,
	authoritySection = 1,
	additionalSection = 2

};

class QueryInstruction{

	public:
		virtual ~QueryInstruction() = default;
		virtual void affectQuery(QueryState& q, CNameResourceRecord* record, std::shared_ptr<ResourceRecord> recP,  QueryContext cont);
		virtual void affectQuery(QueryState& q, AResourceRecord* record, std::shared_ptr<ResourceRecord> recP, QueryContext cont);
		virtual void affectQuery(QueryState& q, NSResourceRecord* record, std::shared_ptr<ResourceRecord> recP, QueryContext cont);
		virtual void affectQuery(QueryState& q, ResourceRecord* record, std::shared_ptr<ResourceRecord> recP, QueryContext cont);

};

class AQueryInstruction : public QueryInstruction{
	
	public:
		~AQueryInstruction() = default;
		void affectQuery(QueryState& q, CNameResourceRecord* record, std::shared_ptr<ResourceRecord> recP, QueryContext cont);
		void affectQuery(QueryState& q, AResourceRecord* record, std::shared_ptr<ResourceRecord> recP, QueryContext cont);
		void affectQuery(QueryState& q, NSResourceRecord* record, std::shared_ptr<ResourceRecord> recP, QueryContext cont);
		void affectQuery(QueryState& q, ResourceRecord* record, std::shared_ptr<ResourceRecord> recP, QueryContext cont);

};

class QueryState{

	public:		
		
		~QueryState();
		QueryState(std::string sname, uint16_t stype, uint16_t sclass, std::shared_ptr<QueryInstruction> qI);
		QueryState(std::string sname, uint16_t stype, uint16_t sclass, QueryState* q);
		QueryState() = default;
		
		void expandAnswers(std::shared_ptr<ResourceRecord> rec);
		void expandNextServerAnswer(std::shared_ptr<ResourceRecord> answer);
		void expandNextServers(std::string server);
		void expandInfo(std::shared_ptr<ResourceRecord> info);
		void expandIps(std::string ip);
		void expandNextServerIps(std::string name, std::string ip);
		
		void affectQuery(ResourceRecord* record, std::shared_ptr<ResourceRecord> recP,  QueryContext cont);
						
		void setMatchScore(std::string domainName);
		static void solveStandardQuery(std::shared_ptr<QueryState> q);
		static void sendStandardQuery(std::shared_ptr<QueryState> q, std::string nameServerIp);
		static void threadFunction(std::shared_ptr<QueryState> currS, std::shared_ptr<QueryState> query);
		
		bool checkEndCondition();
		void displayResult();
		bool haveLocalOpsLeft();
		bool haveGlobalOpsLeft();
		void decrementOps();
		void forceEndQuery(bool localOnly);
		
		void redirectQuery(std::string sname);
		
		
	private:
		//instructions for how each type of resource record should affect this query
		std::shared_ptr<QueryInstruction> _inst;
		
		//name queried
		std::string _sname;
	
		//true if this query state is currently being answered by some thread. this avoids double resolving
		std::atomic<bool> _beingUsed;
	
		//id of the original query
		uint16_t _id;
		
		//qtype of request
		uint16_t _stype;
		
		//qclass of request
		uint16_t _sclass;
		
		int _matchScore;
		
		//name servers this request thinks will be helpful
		std::vector<std::shared_ptr<QueryState> > _nextServers;
		
		//absolute time the request started
		std::time_t _startTime;
		
		//answers received for this query
		std::vector<std::shared_ptr<ResourceRecord> > _answers;
		
		//extra information that does not directly answer the query, but needs to be displayed to the user
		//Example: User makes an A query. Program encounters cname redirect along the way. This cname is not a real answer(A record), but it is still something the user should be aware of.
		std::vector<std::shared_ptr<ResourceRecord> > _extraInfo;
		
		//known ips for the server being queried
		std::vector<std::string> _ips;
		
		
		int _networkCode;
		uint8_t _msgCode;
		
		//number of operations left for this specific request until failure
		//0 means termination. This could be from exhausting ops, finding answers, or fatal errors.
		std::atomic<int> _numOpsLocalLeft;
		
		//number of operations left for the series of requests that led to this one until failure
		//0 means sequence has terminated. Same reasons as above.
		std::shared_ptr<std::atomic<int> > _numOpsGlobalLeft;
		
		std::shared_ptr<std::mutex> _servMutex;
		std::shared_ptr<std::mutex> _ansMutex;
		std::shared_ptr<std::mutex> _infoMutex;
		
		
		
};

void loadSafeties(std::string filePath);
void dumpCacheToFile();





