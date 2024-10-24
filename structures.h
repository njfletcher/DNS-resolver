
#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <iterator>

#define maxDomainNameLen 255

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

class DNSFlags{

	public:
	
		uint8_t _qr;
		uint8_t _opcode;
		uint8_t _aa;
		uint8_t _tc;
		uint8_t _rd;
		uint8_t _ra;
		uint8_t _z;
		uint8_t _rcode;
		
		DNSFlags();
		DNSFlags(uint8_t qr, uint8_t opcode, uint8_t aa, uint8_t tc, uint8_t rd, uint8_t ra, uint8_t z, uint8_t rcode);
		DNSFlags(std::vector<uint8_t>::iterator & iter, const std::vector<uint8_t>::iterator end, bool& succeeded);
		void toBuffer(std::vector<uint8_t> & buffer);
		void print();
	
};

class DNSHeader {

	public:
	
		uint16_t _transId;
		DNSFlags _flags;
		uint16_t _numQuestions;
		uint16_t _numAnswers;
		uint16_t _numAuthRR;
		uint16_t _numAdditRR;
		
		DNSHeader();
		DNSHeader(uint16_t transId, const DNSFlags& flags, uint16_t numQuestions, uint16_t numAnswers, uint16_t numAuthRR, uint16_t numAdditRR);
		DNSHeader(std::vector<uint8_t>::iterator & iter, const std::vector<uint8_t>::iterator end, bool& succeeded);
		void toBuffer(std::vector<uint8_t> & buffer);
		void print();

};


class QuestionRecord{

	public:
		std::vector<uint8_t> _name; // a sequence of octets that repeats the pattern: length octet = n, n octets 
		uint16_t _qType;
		uint16_t _qClass;
		
		QuestionRecord();
		//constructor takes c style string(dont include length octets), the length conversion happens in constructor
		QuestionRecord(const char * name, uint16_t qType, uint16_t qClass);
		QuestionRecord(const std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator & iter, const std::vector<uint8_t>::iterator end, bool& succeeded);
		void toBuffer(std::vector<uint8_t> & buffer);
		void print(uint16_t number);
		

};

class ResourceRecord{

	public:
		std::vector<uint8_t> _name; // a sequence of octets that repeats the pattern: length octet = n, n octets 
		uint16_t _rType;
		uint16_t _rClass;
		uint32_t _ttl;
		uint16_t _rdLength; //specified in octets
		std::vector<uint8_t> _rData; //length of rdLength, not null terminated
		
		ResourceRecord();
		//constructor takes c style string(dont include length octets), the length conversion happens in constructor
		ResourceRecord(const char * name, uint16_t rType, uint16_t rClass, uint32_t ttl, uint16_t rdLength, std::vector<uint8_t> rData);
		ResourceRecord(const std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator & iter, const std::vector<uint8_t>::iterator end, bool& succeeded);
		void toBuffer(std::vector<uint8_t> & buffer);
		void print(uint16_t number);
	

};

class DNSMessage{

	public:
		DNSHeader _hdr;
		std::vector<QuestionRecord> _question;// one or more questions for the name server to answer
		std::vector<ResourceRecord> _answer; // zero or more resource records that answer the query
		std::vector<ResourceRecord> _authority;//zero or more resource records that point to authoritative name servers
		std::vector<ResourceRecord> _additional; // zero or more resource records that are strictly not answers
		
		DNSMessage();
		DNSMessage(const DNSHeader& hdr, std::vector<QuestionRecord>& question, std::vector<ResourceRecord>& answer, std::vector<ResourceRecord>& authority, std::vector<ResourceRecord>& additional);
		DNSMessage(const std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator & iter, const std::vector<uint8_t>::iterator end);
		void toBuffer(std::vector<uint8_t> & buffer);
		void print();

};
