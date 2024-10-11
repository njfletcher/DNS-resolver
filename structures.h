#include <vector>


enum class qrVals{
	query = 0,
	response = 1

};


enum class opcodes{

	standard = 0, //a standard query (QUERY)
	inverse = 1, // an inverse query (IQUERY)
	status = 2 //a server status request (STATUS)

};

class DNSFlags{

	public:
	
		qrVals _qr;
		opcodes _opcode;
		unsigned char _aa;
		unsigned char _tc;
		unsigned char _rd;
		unsigned char _ra;
		unsigned char _z;
		unsigned char _rcode;
		
		DNSFlags(qrVals qr, opcodes opcode, unsigned char aa, unsigned char tc, unsigned char rd, unsigned char ra, unsigned char z, unsigned char rcode);
		void toBuffer(std::vector<char> & buffer);
	

};

class DNSHeader {

	public:
	
		unsigned short _transId;
		DNSFlags* _flags;
		unsigned short _numQuestions;
		unsigned short _numAnswers;
		unsigned short _numAuthRR;
		unsigned short _numAdditRR;
		
		DNSHeader(unsigned short transId, DNSFlags* flags, unsigned short numQuestions, unsigned short numAnswers, unsigned short numAuthRR, unsigned short numAdditRR);
		void toBuffer(std::vector<char> & buffer);


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

class QuestionRecord{

	public:
		const char* _name; // c style string
		ResourceTypes _qType;
		ResourceClasses _qClass;
		
		QuestionRecord(const char * name, ResourceTypes qType, ResourceClasses qClass);
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
		DNSHeader* _hdr;
		QuestionRecord* _question;// one or more questions for the name server to answer
		ResourceRecord* _answer; // zero or more resource records that answer the query
		ResourceRecord* _authority;//zero or more resource records that point to authoritative name servers
		ResourceRecord* _additional; // zero or more resource records that are strictly not answers
		
		DNSMessage(DNSHeader* hdr, QuestionRecord* question, ResourceRecord* answer, ResourceRecord* authority, ResourceRecord* additional);
		void toBuffer(std::vector<char> & buffer);

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


