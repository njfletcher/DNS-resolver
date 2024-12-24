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


class QueryState{

	public:		
		
		~QueryState();
		QueryState(std::string sname, uint16_t stype, uint16_t sclass);
		QueryState(std::string sname, uint16_t stype, uint16_t sclass, QueryState* q);
		
		void expandAnswers(std::string answer);
		void expandNextServerAnswer(std::string server, std::string answer);
		void expandNextServers(std::string server);
		std::vector<std::string> getAnswers();
						
		void setMatchScore(std::string domainName);
		static void solveStandardQuery(std::shared_ptr<QueryState> q);
		static void sendStandardQuery(std::shared_ptr<QueryState> q, std::string nameServerIp);
		
		bool checkEndCondition();
		void displayResult();
		bool haveLocalOpsLeft();
		bool haveGlobalOpsLeft();
		void decrementOps();
		void forceEndQuery(bool localOnly);
		
		
	private:
	
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
		std::vector<std::string> _answers;
		
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
		
		
		
};

void loadSafeties(std::string filePath);
void dumpCacheToFile();




