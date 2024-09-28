
struct DNSFlags{

	unsigned char qr;
	unsigned char opcode;
	unsigned char aa;
	unsigned char tc;
	unsigned char rd;
	unsigned char ra;
	unsigned char z;
	unsigned char rcode;
	

};

struct DNSHeader {

	unsigned short transId;
	DNSFlags* flags;
	unsigned short numQuestions;
	unsigned short numAnswers;
	unsigned short numAuthRR;
	unsigned short numAdditRR;


};

struct QuestionRecord{

	char* name;
	unsigned short qType;
	unsigned short qClass;

};

struct ResourceRecord{

	char* name;
	unsigned short rType;
	unsigned short rClass;
	unsigned int ttl;
	unsigned short rdLength; //specified in octets
	unsigned short rdData;

};


