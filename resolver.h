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

#define maxDomainNameLen 255

//operation capping to make sure threads dont go out of control or network errors cause program to run forever.
//a thread spawn or network request is one operation decrement
#define perQueryOpCap 20
#define perSequenceOpCap 100

class DNSMessage;

enum class SessionStates{

	answered = 0,
	continued = 1,
	failed = 2

};

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
	server = 2, //The name server wasunable to process this query due to a problem with the name server
	name = 3, //Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does  not exist.
	implement = 4, //The name server does not support the requested kind of query
	refused = 5 //The name server refuses to perform the specified operation for policy reasons.  For example, 
	//a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data

};


class QueryState{

	public:
	
		//is this querysInformation able to be used?
		//will be false if this query's answers are being gathered or some query is being resolved using this one 
		bool _readyForUse;
	
		//id of the original query
		uint16_t _id;
		
		//name queried
		std::string _sname;
		
		//qtype of request
		uint16_t _stype;
		
		//qclass of request
		uint16_t _sclass;
		
		int _matchScore;
		
		//name servers this request thinks will be helpful
		std::vector<QueryState> _nextServers;
		
				
		//absolute time the request started
		uint16_t _startTime;
		
		//answers received for this query
		std::vector<std::string> _answers;
		
		int _networkCode;
		uint8_t _msgCode;
		
		//number of operations left for this specific request until failure
		//0 means termination. This could be from exhausting ops, finding answers, or fatal errors.
		unsigned int _numOpsLocalLeft;
		
		std::shared_ptr<std::mutex> _opMutex;
		std::shared_ptr<std::mutex> _servMutex;
		std::shared_ptr<std::mutex> _ansMutex;
		
		//number of operations left for the series of requests that led to this one until failure
		//0 means sequence has terminated. Same reasons as above.
		std::shared_ptr<unsigned int> _numOpsGlobalLeft;
		
		~QueryState();
		QueryState(std::string sname, uint16_t stype, uint16_t sclass);
		QueryState(std::string sname, uint16_t stype, uint16_t sclass, QueryState& q);
		
		void expandAnswers(std::string answer);
		void expandNextServerAnswer(std::string server, std::string answer);
		void expandNextServers(std::string server);
				
		bool haveLocalOpsLeft();
		bool haveGlobalOpsLeft();
		void extractDataFromResponse(DNSMessage& msg);
		
		void setMatchScore(std::string domainName);
		
	private:
		bool checkForFatalErrors();
		void cacheRecords(DNSMessage& msg);
		bool checkForResponseErrors(DNSMessage& msg);
		
};

void loadSafeties(std::string filePath);
void solveStandardQuery(QueryState* query);
void dumpCacheToFile();




