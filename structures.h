#include <vector>


class DNSFlags{

	public:
	
		unsigned char qr;
		unsigned char opcode;
		unsigned char aa;
		unsigned char tc;
		unsigned char rd;
		unsigned char ra;
		unsigned char z;
		unsigned char rcode;
		
		void toBuffer(std::vector<char> & buffer);
	

};

class DNSHeader {

	public:
	
		unsigned short transId;
		DNSFlags* flags;
		unsigned short numQuestions;
		unsigned short numAnswers;
		unsigned short numAuthRR;
		unsigned short numAdditRR;
		
		void toBuffer(std::vector<char> & buffer);


};

class QuestionRecord{

	public:
		char* name; // c style string
		unsigned short qType;
		unsigned short qClass;
		
		void toBuffer(std::vector<char> & buffer);
		

};

struct ResourceRecord{

	public:
		char* name; // c style string
		unsigned short rType;
		unsigned short rClass;
		unsigned int ttl;
		unsigned short rdLength; //specified in octets
		char* rData; //length of rdLength, not null terminated
		
		void toBuffer(std::vector<char> & buffer);
	

};

struct DNSMessage{

	public:
		DNSHeader* hdr;
		QuestionRecord* question;// one or more questions for the name server to answer
		ResourceRecord* answer; // zero or more resource records that answer the query
		ResourceRecord* authority;//zero or more resource records that point to authoritative name servers
		ResourceRecord* additional; // zero or more resource records that are strictly not answers
		
		void toBuffer(std::vector<char> & buffer);

};

enum class ResourceTypes{

	a, // a host address
	ns, // an authoritative name server
	cname, //the canonical name for an alias
	soa, //marks the start of a zone of authority
	mb, //a mailbox domain name
	mg, // a mail group member
	mr, // a mail rename domain name,
	nullR, // a null resource record
	wks, // a well known server description
	ptr, // a domain name pointer
	hinfo, // host information
	minfo, //mailbox or mail list information
	mx, //mail exchange
	txt, //text strings
	afxr, // a request for a transfer of an entire zone
	mailb,//a request for mailbox related records( MB, MG, or MR)
	all // a request for all records(*)

};

enum class ResourceClasses{

	in, //the internet
	ch, //the CHAOS class
	hs, //Hesiod
	all //all classes

};

enum class ResponseCodes{

	none, // no errors
	format, // the name server was unable to interpret the query
	server, //The name server wasunable to process this query due to a problem with the name server
	name, //Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does  not exist.
	implement, //The name server does not support the requested kind of query
	refused, //The name server refuses to perform the specified operation for policy reasons.  For example, 
	//a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data
	reserved
	

};


